// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/major.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <csignal>
#include <ctime>
#include <iostream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/pty_util.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::AnyOf;
using ::testing::Contains;
using ::testing::Eq;
using ::testing::Not;
using SubprocessCallback = std::function<void()>;

// Tests Unix98 pseudoterminals.
//
// These tests assume that /dev/ptmx exists and is associated with a devpts
// filesystem mounted at /dev/pts/. While a Linux distribution could
// theoretically place those anywhere, glibc expects those locations, so they
// are effectively fixed.

// Minor device number for an unopened ptmx file.
constexpr int kPtmxMinor = 2;

// The timeout when polling for data from a pty. When data is written to one end
// of a pty, Linux asynchronously makes it available to the other end, so we
// have to wait.
constexpr absl::Duration kTimeout = absl::Seconds(20);

// Similar to kTimeout, but shorter: This timeout is used for tests where
// the expected behavior is to observe a timeout, which helps speed up tests.
constexpr absl::Duration kTimeoutShort = absl::Seconds(2);

// The maximum line size in bytes returned per read from a pty file.
constexpr int kMaxLineSize = 4096;

constexpr char kMasterPath[] = "/dev/ptmx";

// Returns the termios-style control character for the passed character.
//
// e.g., for Ctrl-C, i.e., ^C, call ControlCharacter('C').
//
// Standard control characters are ASCII bytes 0 through 31.
constexpr char ControlCharacter(char c) {
  // A is 1, B is 2, etc.
  return c - 'A' + 1;
}

// fields.

// Return the default termios settings for a new terminal.
struct kernel_termios DefaultTermios() {
  struct kernel_termios t = {};
  t.c_iflag = IXON | ICRNL;
  t.c_oflag = OPOST | ONLCR;
  t.c_cflag = B38400 | CSIZE | CS8 | CREAD;
  t.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
  t.c_line = 0;
  t.c_cc[VINTR] = ControlCharacter('C');
  t.c_cc[VQUIT] = ControlCharacter('\\');
  t.c_cc[VERASE] = '\x7f';
  t.c_cc[VKILL] = ControlCharacter('U');
  t.c_cc[VEOF] = ControlCharacter('D');
  t.c_cc[VTIME] = '\0';
  t.c_cc[VMIN] = 1;
  t.c_cc[VSWTC] = '\0';
  t.c_cc[VSTART] = ControlCharacter('Q');
  t.c_cc[VSTOP] = ControlCharacter('S');
  t.c_cc[VSUSP] = ControlCharacter('Z');
  t.c_cc[VEOL] = '\0';
  t.c_cc[VREPRINT] = ControlCharacter('R');
  t.c_cc[VDISCARD] = ControlCharacter('O');
  t.c_cc[VWERASE] = ControlCharacter('W');
  t.c_cc[VLNEXT] = ControlCharacter('V');
  t.c_cc[VEOL2] = '\0';
  return t;
}

// PollAndReadFd tries to read count bytes from buf within timeout.
//
// Returns a partial read if some bytes were read.
//
// fd must be non-blocking.
PosixErrorOr<size_t> PollAndReadFd(int fd, void *buf, size_t count,
                                   absl::Duration timeout) {
  absl::Time end = absl::Now() + timeout;

  size_t completed = 0;
  absl::Duration remaining;
  while ((remaining = end - absl::Now()) > absl::ZeroDuration()) {
    struct pollfd pfd = {fd, POLLIN, 0};
    int ret = RetryEINTR(poll)(&pfd, 1, absl::ToInt64Milliseconds(remaining));
    if (ret < 0) {
      return PosixError(errno, "poll failed");
    } else if (ret == 0) {
      // Timed out.
      continue;
    } else if (ret != 1) {
      return PosixError(EINVAL, absl::StrCat("Bad poll ret ", ret));
    }

    ssize_t n =
        ReadFd(fd, static_cast<char *>(buf) + completed, count - completed);
    if (n < 0) {
      if (errno == EAGAIN) {
        // Linux sometimes returns EAGAIN from this read, despite the fact that
        // poll returned success. Let's just do what do as we are told and try
        // again.
        continue;
      }
      return PosixError(errno, "read failed");
    } else if (n > 0 && (pfd.revents & POLLIN) == 0) {
      return PosixError(EINVAL, "Poll said not readable but data was read");
    }
    completed += n;
    if (completed >= count) {
      return completed;
    }
  }

  if (completed) {
    return completed;
  }
  return PosixError(ETIMEDOUT, "Poll timed out");
}

TEST(PtyTrunc, Truncate) {
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader and have
  // no controlling terminal.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  const Cleanup cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGHUP, sa));

  // Opening PTYs with O_TRUNC shouldn't cause an error, but calls to
  // (f)truncate should.
  FileDescriptor master =
      ASSERT_NO_ERRNO_AND_VALUE(Open(kMasterPath, O_RDWR | O_TRUNC));
  int n = ASSERT_NO_ERRNO_AND_VALUE(ReplicaID(master));
  std::string spath = absl::StrCat("/dev/pts/", n);
  FileDescriptor replica =
      ASSERT_NO_ERRNO_AND_VALUE(Open(spath, O_RDWR | O_NONBLOCK | O_TRUNC));
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallSucceeds());

  EXPECT_THAT(truncate(kMasterPath, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(truncate(spath.c_str(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(ftruncate(master.get(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(ftruncate(replica.get(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST(BasicPtyTest, StatUnopenedMaster) {
  struct stat s;
  ASSERT_THAT(stat(kMasterPath, &s), SyscallSucceeds());

  EXPECT_EQ(s.st_rdev, makedev(TTYAUX_MAJOR, kPtmxMinor));
  EXPECT_EQ(s.st_size, 0);
  EXPECT_EQ(s.st_blocks, 0);

  // ptmx attached to a specific devpts mount uses block size 1024. See
  // fs/devpts/inode.c:devpts_fill_super.
  //
  // The global ptmx device uses the block size of the filesystem it is created
  // on (which is usually 4096 for disk filesystems).
  EXPECT_THAT(s.st_blksize, AnyOf(Eq(1024), Eq(4096)));
}

// Waits for count bytes to be readable from fd. Unlike poll, which can return
// before all data is moved into a pty's read buffer, this function waits for
// all count bytes to become readable.
PosixErrorOr<int> WaitUntilReceived(int fd, int count) {
  int buffered = -1;
  absl::Duration remaining;
  absl::Time end = absl::Now() + kTimeout;
  while ((remaining = end - absl::Now()) > absl::ZeroDuration()) {
    if (ioctl(fd, FIONREAD, &buffered) < 0) {
      return PosixError(errno, "failed FIONREAD ioctl");
    }
    if (buffered >= count) {
      return buffered;
    }
    absl::SleepFor(absl::Milliseconds(500));
  }
  return PosixError(
      ETIMEDOUT,
      absl::StrFormat(
          "FIONREAD timed out, receiving only %d of %d expected bytes",
          buffered, count));
}

// Verifies that there is nothing left to read from fd.
void ExpectFinished(const FileDescriptor &fd) {
  // Nothing more to read.
  char c;
  EXPECT_THAT(ReadFd(fd.get(), &c, 1), SyscallFailsWithErrno(EAGAIN));
}

// Verifies that we can read expected bytes from fd into buf.
void ExpectReadable(const FileDescriptor &fd, int expected, char *buf) {
  size_t n = ASSERT_NO_ERRNO_AND_VALUE(
      PollAndReadFd(fd.get(), buf, expected, kTimeout));
  EXPECT_EQ(expected, n);
}

TEST(BasicPtyTest, OpenMasterReplica) {
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master));
}

TEST(BasicPtyTest, OpenSetsControllingTTY) {
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  struct sigaction old_sa;
  ASSERT_THAT(sigaction(SIGHUP, &sa, &old_sa), SyscallSucceeds());
  auto cleanup = Cleanup([old_sa] {
    EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());
  });

  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica =
      ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master, O_NONBLOCK | O_RDWR));

  // Opening replica should make it our controlling TTY, and therefore we are
  // able to give it up.
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallSucceeds());
}

TEST(BasicPtyTest, OpenMasterDoesNotSetsControllingTTY) {
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));

  // Opening master does not set the controlling TTY, and therefore we are
  // unable to give it up.
  ASSERT_THAT(ioctl(master.get(), TIOCNOTTY), SyscallFailsWithErrno(ENOTTY));
}

TEST(BasicPtyTest, OpenNOCTTY) {
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica = ASSERT_NO_ERRNO_AND_VALUE(
      OpenReplica(master, O_NOCTTY | O_NONBLOCK | O_RDWR));

  // Opening replica with O_NOCTTY won't make it our controlling TTY, and
  // therefore we are unable to give it up.
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallFailsWithErrno(ENOTTY));
}

TEST(BasicPtyTest, TIOCGPTPEERSucceeds) {
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  int index = ASSERT_NO_ERRNO_AND_VALUE(ReplicaID(master));

  int peer = -1;
  ASSERT_THAT(peer = ioctl(master.get(), TIOCGPTPEER, O_RDWR | O_NOCTTY),
              SyscallSucceeds());
  FileDescriptor replica(peer);

  // The peer is the replica connected to this master: data written to the
  // master is readable from it.
  constexpr char kData[] = "xyz\n";
  ASSERT_THAT(WriteFd(master.get(), kData, sizeof(kData) - 1),
              SyscallSucceedsWithValue(sizeof(kData) - 1));
  char buf[sizeof(kData) - 1] = {};
  ExpectReadable(replica, sizeof(buf), buf);
  EXPECT_EQ(memcmp(buf, kData, sizeof(buf)), 0);

  // The peer resolves to the replica's path, like any other open of it.
  std::string link = ASSERT_NO_ERRNO_AND_VALUE(
      ReadLink(absl::StrCat("/proc/self/fd/", replica.get())));
  EXPECT_EQ(link, absl::StrCat("/dev/pts/", index));
}

// Opening the peer via TIOCGPTPEER without O_NOCTTY makes it the controlling
// TTY, just like opening the replica by path does.
TEST(BasicPtyTest, TIOCGPTPEERSetsControllingTTY) {
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  struct sigaction old_sa;
  ASSERT_THAT(sigaction(SIGHUP, &sa, &old_sa), SyscallSucceeds());
  auto cleanup = Cleanup([old_sa] {
    EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());
  });

  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  ASSERT_NO_ERRNO(ReplicaID(master));  // Unlock the pty.

  int peer = -1;
  ASSERT_THAT(peer = ioctl(master.get(), TIOCGPTPEER, O_RDWR),
              SyscallSucceeds());
  FileDescriptor replica(peer);

  // Opening the peer should make it our controlling TTY, and therefore we are
  // able to give it up.
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallSucceeds());
}

// Opening the peer via TIOCGPTPEER with O_NOCTTY does not make it the
// controlling TTY.
TEST(BasicPtyTest, TIOCGPTPEERNoctty) {
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));

  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  ASSERT_NO_ERRNO(ReplicaID(master));  // Unlock the pty.

  int peer = -1;
  ASSERT_THAT(peer = ioctl(master.get(), TIOCGPTPEER, O_NOCTTY | O_RDWR),
              SyscallSucceeds());
  FileDescriptor replica(peer);

  // Opening the peer with O_NOCTTY won't make it our controlling TTY, and
  // therefore we are unable to give it up.
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallFailsWithErrno(ENOTTY));
}

// The replica entry in /dev/pts/ disappears when the master is closed, even if
// the replica is still open.
TEST(BasicPtyTest, ReplicaEntryGoneAfterMasterClose) {
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master));

  // Get pty index.
  int index = -1;
  ASSERT_THAT(ioctl(master.get(), TIOCGPTN, &index), SyscallSucceeds());

  std::string path = absl::StrCat("/dev/pts/", index);

  struct stat st;
  EXPECT_THAT(stat(path.c_str(), &st), SyscallSucceeds());

  master.reset();

  EXPECT_THAT(stat(path.c_str(), &st), SyscallFailsWithErrno(ENOENT));
}

TEST(BasicPtyTest, Getdents) {
  FileDescriptor master1 = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  int index1 = -1;
  ASSERT_THAT(ioctl(master1.get(), TIOCGPTN, &index1), SyscallSucceeds());
  FileDescriptor replica1 = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master1));

  FileDescriptor master2 = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  int index2 = -1;
  ASSERT_THAT(ioctl(master2.get(), TIOCGPTN, &index2), SyscallSucceeds());
  FileDescriptor replica2 = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master2));

  // The directory contains ptmx, index1, and index2. (Plus any additional PTYs
  // unrelated to this test.)

  std::vector<std::string> contents =
      ASSERT_NO_ERRNO_AND_VALUE(ListDir("/dev/pts/", true));
  EXPECT_THAT(contents, Contains(absl::StrCat(index1)));
  EXPECT_THAT(contents, Contains(absl::StrCat(index2)));

  master2.reset();

  // The directory contains ptmx and index1, but not index2 since the master is
  // closed. (Plus any additional PTYs unrelated to this test.)

  contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir("/dev/pts/", true));
  EXPECT_THAT(contents, Contains(absl::StrCat(index1)));
  EXPECT_THAT(contents, Not(Contains(absl::StrCat(index2))));

  // N.B. devpts supports legacy "single-instance" mode and new "multi-instance"
  // mode. In legacy mode, devpts does not contain a "ptmx" device (the distro
  // must use mknod to create it somewhere, presumably /dev/ptmx).
  // Multi-instance mode does include a "ptmx" device tied to that mount.
  //
  // We don't check for the presence or absence of "ptmx", as distros vary in
  // their usage of the two modes.
}

TEST(BasicPtyTest, NewInstance) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("devpts_test", dir.path(), "devpts", 0, "newinstance", 0));
  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const mount2 = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("devpts_test2", dir.path(), "devpts", 0, "newinstance", 0));

  // Opening PTYs with O_TRUNC shouldn't cause an error, but calls to
  // (f)truncate should.
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), "ptmx"), O_RDWR | O_TRUNC));
  int n = ASSERT_NO_ERRNO_AND_VALUE(ReplicaID(master));
  std::string spath2 = absl::StrCat(dir2.path(), "/", n);
  ASSERT_THAT(open(spath2.c_str(), O_RDWR), SyscallFailsWithErrno(ENOENT));
  std::string spath = absl::StrCat(dir.path(), "/", n);
  FileDescriptor replica =
      ASSERT_NO_ERRNO_AND_VALUE(Open(spath.c_str(), O_RDWR | O_NOCTTY));
}

TEST(BasicPtyTest, SetMode) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("devpts_test", dir.path(), "devpts", 0,
            "newinstance,mode=0600,ptmxmode=0620", 0));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path()), O_RDONLY | O_DIRECTORY));
  mount.Release();

  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_mode, 0600 | S_IFDIR);
  ASSERT_THAT(fstatat(fd.get(), "ptmx", &st, 0), SyscallSucceeds());
  EXPECT_EQ(st.st_mode, 0620 | S_IFCHR);
}

TEST(BasicPtyTest, OpenDevTTY) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Run in forked process so we don't pollute the controlling terminal of the
  // main test process, which other tests expect to be unset.
  const auto rest = [&] {
    // We must be session leader to set controlling terminal,
    // which will be opened by /dev/tty.
    setsid();

    // Ignore SIGHUP: when the master fd is closed during cleanup, the
    // kernel sends SIGHUP to the foreground process group of the
    // controlling terminal session. Since this child *is* the session leader,
    // it would be killed by the default SIGHUP disposition before _exit(0).
    TEST_PCHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR);

    FileDescriptor master =
        TEST_CHECK_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));

    // Opening the replica without O_NOCTTY will set controlling terminal.
    FileDescriptor replica =
        TEST_CHECK_NO_ERRNO_AND_VALUE(OpenReplica(master, O_RDWR | O_NONBLOCK));

    // Terminal now available at /dev/tty.
    FileDescriptor devtty =
        TEST_CHECK_NO_ERRNO_AND_VALUE(Open("/dev/tty", O_RDWR | O_NONBLOCK));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(BasicPtyTest, OpenDevTTYNoCTTY) {
  // Become session leader, otherwise we will never have hope of setting a
  // controlling terminal. This test verifies that we fail to open /dev/tty for
  // other (expected) reasons.
  setsid();

  // No controlling terminal, so can't open /dev/tty.
  EXPECT_THAT(open("/dev/tty", O_RDWR | O_NONBLOCK),
              SyscallFailsWithErrno(ENXIO));

  // Open a master, but still no terminal available.
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  EXPECT_THAT(open("/dev/tty", O_RDWR | O_NONBLOCK),
              SyscallFailsWithErrno(ENXIO));

  // Open terminal with NOCTTY. Still can't open /dev/tty.
  FileDescriptor replica_noctty = ASSERT_NO_ERRNO_AND_VALUE(
      OpenReplica(master, O_RDWR | O_NONBLOCK | O_NOCTTY));
  EXPECT_THAT(open("/dev/tty", O_RDWR | O_NONBLOCK),
              SyscallFailsWithErrno(ENXIO));
}

class PtyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    master_ = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR | O_NONBLOCK));
    replica_ = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master_));
  }

  void DisableCanonical() {
    struct kernel_termios t = {};
    EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
    t.c_lflag &= ~ICANON;
    EXPECT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  }

  void EnableCanonical() {
    struct kernel_termios t = {};
    EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
    t.c_lflag |= ICANON;
    EXPECT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  }

  void DisableCanonicalAndEcho() {
    struct kernel_termios t = {};
    EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    EXPECT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  }

  void FillUntilWriteReturnsEAGAIN(const FileDescriptor& fd) {
    std::string buf(8192, 'x');
    for (;;) {
      ssize_t n = RetryEINTR(write)(fd.get(), buf.data(), buf.size());
      if (n < 0) {
        ASSERT_EQ(errno, EAGAIN);
        break;
      }
      ASSERT_GT(n, 0);
    }

    // A short write returning EAGAIN is a stronger signal that the queue is
    // close to full. For PTYs, a large write can fail once the remaining room
    // drops below 8192 bytes even if there is still space for a few more
    // bytes.
    char byte = 'x';
    for (;;) {
      ssize_t n = RetryEINTR(write)(fd.get(), &byte, 1);
      if (n < 0) {
        ASSERT_EQ(errno, EAGAIN);
        break;
      }
      ASSERT_EQ(n, 1);
    }
  }

  void FillUntilBlocked(const FileDescriptor& fd) {
    FillUntilWriteReturnsEAGAIN(fd);

    struct pollfd pfd = {fd.get(), POLLOUT, 0};
    ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, 0), SyscallSucceedsWithValue(0));
  }

  void EnablePacketMode() {
    int mode = 1;
    ASSERT_THAT(ioctl(master_.get(), TIOCPKT, &mode), SyscallSucceeds());
  }

  void ExpectMasterPacketStatus(char expected) {
    struct pollfd pfd = {master_.get(), POLLIN | POLLPRI, 0};
    ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, absl::ToInt64Milliseconds(kTimeout)),
                SyscallSucceedsWithValue(1));
    EXPECT_EQ(pfd.revents & (POLLIN | POLLPRI), POLLIN | POLLPRI);

    char status = 0;
    EXPECT_THAT(ReadFd(master_.get(), &status, 1), SyscallSucceedsWithValue(1));
    EXPECT_EQ(status, expected);
  }

  void ExpectMasterHasNoPacketStatus() {
    struct pollfd pfd = {master_.get(), POLLIN | POLLPRI, 0};
    EXPECT_THAT(poll(&pfd, 1, 0), SyscallSucceedsWithValue(0));
  }

  // Writes master_input to the master file descriptor and verifies that
  // the replica and the echo output match what is expected.
  void TestCanonicalIO(const char *master_input,
                       const char *expected_replica_output,
                       const char *expected_echo_output) {
    ASSERT_THAT(WriteFd(master_.get(), master_input, strlen(master_input)),
                SyscallSucceedsWithValue(strlen(master_input)));

    std::string buf(strlen(expected_replica_output), '\0');
    ASSERT_NO_ERRNO(
        WaitUntilReceived(replica_.get(), strlen(expected_replica_output)));
    ExpectReadable(replica_, strlen(expected_replica_output), &buf[0]);
    EXPECT_STREQ(buf.c_str(), expected_replica_output);

    std::string echo_buf(strlen(expected_echo_output), '\0');
    ExpectReadable(master_, strlen(expected_echo_output), &echo_buf[0]);
    EXPECT_STREQ(echo_buf.c_str(), expected_echo_output);

    ExpectFinished(master_);
    ExpectFinished(replica_);
  }

  // Master and replica ends of the PTY. Non-blocking.
  FileDescriptor master_;
  FileDescriptor replica_;
};

// NOTE(gvisor.dev/issue/9951): Regression test.
TEST_F(PtyTest, ReplicaCloseNotify) {
  // Open a second replica.
  FileDescriptor replica2_ = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master_));
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(master_.get(), &read_set);
  int max_fd = master_.get() + 1;

  // Set timeout to 0.2 seconds.
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 200000;

  // Ensure that there are no readable events.
  FD_ZERO(&read_set);
  FD_SET(master_.get(), &read_set);
  EXPECT_THAT(select(max_fd, &read_set, NULL, NULL, &tv),
              SyscallSucceedsWithValue(0));

  // Close the second replica and no readable event should occur.
  replica2_.reset();
  FD_ZERO(&read_set);
  FD_SET(master_.get(), &read_set);
  EXPECT_THAT(select(max_fd, &read_set, NULL, NULL, &tv),
              SyscallSucceedsWithValue(0));

  // Close the last remaining replica and a readable event should occur.
  replica_.reset();
  FD_ZERO(&read_set);
  FD_SET(master_.get(), &read_set);
  EXPECT_THAT(select(max_fd, &read_set, NULL, NULL, &tv),
              SyscallSucceedsWithValue(1));
  EXPECT_TRUE(FD_ISSET(master_.get(), &read_set));

  // Check that the right events are occurring.
  struct pollfd pfd;
  pfd.fd = master_.get();
  pfd.events = POLLIN | POLLOUT | POLLRDHUP | POLLRDNORM | POLLWRNORM;
  EXPECT_THAT(poll(&pfd, 1, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(POLLHUP | POLLOUT | POLLWRNORM, pfd.revents);
}

// Master to replica sanity test.
TEST_F(PtyTest, WriteMasterToReplica) {
  // N.B. by default, the replica reads nothing until the master writes a
  // newline.
  constexpr char kBuf[] = "hello\n";

  EXPECT_THAT(WriteFd(master_.get(), kBuf, sizeof(kBuf) - 1),
              SyscallSucceedsWithValue(sizeof(kBuf) - 1));

  // Linux moves data from the master to the replica via async work scheduled
  // via tty_flip_buffer_push. Since it is asynchronous, the data may not be
  // available for reading immediately. Instead we must poll and assert that it
  // becomes available "soon".

  char buf[sizeof(kBuf)] = {};
  ExpectReadable(replica_, sizeof(buf) - 1, buf);

  EXPECT_EQ(memcmp(buf, kBuf, sizeof(kBuf)), 0);
}

// Replica to master sanity test.
TEST_F(PtyTest, WriteReplicaToMaster) {
  // N.B. by default, the master reads nothing until the replica writes a
  // newline, and the master gets a carriage return.
  constexpr char kInput[] = "hello\n";
  constexpr char kExpected[] = "hello\r\n";

  EXPECT_THAT(WriteFd(replica_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));

  // Linux moves data from the master to the replica via async work scheduled
  // via tty_flip_buffer_push. Since it is asynchronous, the data may not be
  // available for reading immediately. Instead we must poll and assert that it
  // becomes available "soon".

  char buf[sizeof(kExpected)] = {};
  ExpectReadable(master_, sizeof(buf) - 1, buf);

  EXPECT_EQ(memcmp(buf, kExpected, sizeof(kExpected)), 0);
}

TEST_F(PtyTest, PacketModeWriteMasterToReplica) {
  // Set packet mode.
  int mode = 1;
  ASSERT_THAT(ioctl(master_.get(), TIOCPKT, &mode), SyscallSucceeds());

  // N.B. by default, the replica reads nothing until the master writes a
  // newline.
  constexpr char kBuf[] = "hello\n";

  EXPECT_THAT(WriteFd(master_.get(), kBuf, sizeof(kBuf) - 1),
              SyscallSucceedsWithValue(sizeof(kBuf) - 1));

  // Linux moves data from the master to the replica via async work scheduled
  // via tty_flip_buffer_push. Since it is asynchronous, the data may not be
  // available for reading immediately. Instead we must poll and assert that it
  // becomes available "soon".

  // Replica does not see the leading packet mode byte, so expect the same as
  // input.
  char buf[sizeof(kBuf)] = {};
  ExpectReadable(replica_, sizeof(buf) - 1, buf);

  EXPECT_EQ(memcmp(buf, kBuf, sizeof(kBuf)), 0);
}

TEST_F(PtyTest, PacketModeWriteReplicaToMaster) {
  // Set packet mode.
  int mode = 1;
  ASSERT_THAT(ioctl(master_.get(), TIOCPKT, &mode), SyscallSucceeds());

  // N.B. by default, the master reads nothing until the replica writes a
  // newline, and the master gets a carriage return.
  constexpr char kInput[] = "hello\n";

  // This is the interesting case. When in packet mode, the master should expect
  // the read buffer to have a leading 0 (TIOCPKT_DATA) byte.
  constexpr char kExpected[] = "\0hello\r\n";

  EXPECT_THAT(WriteFd(replica_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));

  // Linux moves data from the master to the replica via async work scheduled
  // via tty_flip_buffer_push. Since it is asynchronous, the data may not be
  // available for reading immediately. Instead we must poll and assert that it
  // becomes available "soon".

  char buf[sizeof(kExpected)] = {};
  ExpectReadable(master_, sizeof(buf) - 1, buf);

  EXPECT_EQ(memcmp(buf, kExpected, sizeof(kExpected)), 0);
}

// Verifies that data enqueued into the replica is still readable by the master
// after the replica is closed.
TEST_F(PtyTest, WriteReplicaToMasterReadAfterReplicaClosed) {
  // N.B. by default, the master reads nothing until the replica writes a
  // newline, and the master gets a carriage return.
  constexpr char kInput[] = "hello\n";
  constexpr char kExpected[] = "hello\r\n";

  EXPECT_THAT(WriteFd(replica_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));

  // Close the replica.
  replica_.reset();

  char buf[sizeof(kExpected)] = {};
  ExpectReadable(master_, sizeof(buf) - 1, buf);
  EXPECT_EQ(memcmp(buf, kExpected, sizeof(kExpected)), 0);

  // After all data has been read, the master should return EIO.
  char c;
  EXPECT_THAT(ReadFd(master_.get(), &c, 1), SyscallFailsWithErrno(EIO));
}

TEST_F(PtyTest, PacketModeFailsOnReplica) {
  int mode = 1;
  EXPECT_THAT(ioctl(replica_.get(), TIOCPKT, &mode),
              SyscallFailsWithErrno(ENOTTY));
}

TEST_F(PtyTest, WriteInvalidUTF8) {
  char c = 0xff;
  ASSERT_THAT(syscall(__NR_write, master_.get(), &c, sizeof(c)),
              SyscallSucceedsWithValue(sizeof(c)));
}

// Both the master and replica report the standard default termios settings.
//
// Note that TCGETS on the master actually redirects to the replica (see comment
// on MasterTermiosUnchangable).
TEST_F(PtyTest, DefaultTermios) {
  struct kernel_termios t = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
  EXPECT_EQ(t, DefaultTermios());

  EXPECT_THAT(ioctl(master_.get(), TCGETS, &t), SyscallSucceeds());
  EXPECT_EQ(t, DefaultTermios());
}

TEST_F(PtyTest, Termios2) {
  struct kernel_termios t = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());

  struct kernel_termios2 t2 = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS2, &t2), SyscallSucceeds());

  EXPECT_EQ(t.c_iflag, t2.c_iflag);
  EXPECT_EQ(t.c_oflag, t2.c_oflag);
  EXPECT_EQ(t.c_cflag, t2.c_cflag);
  EXPECT_EQ(t.c_lflag, t2.c_lflag);
  EXPECT_EQ(t.c_line, t2.c_line);
  for (int i = 0; i < KERNEL_NCCS; ++i) {
    EXPECT_EQ(t.c_cc[i], t2.c_cc[i]);
  }

  // Default speed is 38400.
  EXPECT_EQ(t2.c_ispeed, 38400);
  EXPECT_EQ(t2.c_ospeed, 38400);

  // Test TCSETS2.
  t2.c_lflag ^= ICANON;
  EXPECT_THAT(ioctl(replica_.get(), TCSETS2, &t2), SyscallSucceeds());
  struct kernel_termios2 t3 = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS2, &t3), SyscallSucceeds());
  EXPECT_EQ(t2.c_lflag, t3.c_lflag);

  // Test TCSETSW2.
  t2.c_lflag ^= ICANON;
  EXPECT_THAT(ioctl(replica_.get(), TCSETSW2, &t2), SyscallSucceeds());
  EXPECT_THAT(ioctl(replica_.get(), TCGETS2, &t3), SyscallSucceeds());
  EXPECT_EQ(t2.c_lflag, t3.c_lflag);

  // Test TCSETSF2.
  t2.c_lflag ^= ICANON;
  EXPECT_THAT(ioctl(replica_.get(), TCSETSF2, &t2), SyscallSucceeds());
  EXPECT_THAT(ioctl(replica_.get(), TCGETS2, &t3), SyscallSucceeds());
  EXPECT_EQ(t2.c_lflag, t3.c_lflag);
}

TEST_F(PtyTest, TermiosFault) {
  struct kernel_termios t_orig = {};
  ASSERT_THAT(ioctl(replica_.get(), TCGETS, &t_orig), SyscallSucceeds());

  struct kernel_termios t = t_orig;
  t.c_lflag ^= ICANON;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  struct kernel_termios t_new = {};
  ASSERT_THAT(ioctl(replica_.get(), TCGETS, &t_new), SyscallSucceeds());
  EXPECT_EQ(t.c_lflag, t_new.c_lflag);

  // Call TCSETS with an invalid pointer.
  EXPECT_THAT(ioctl(replica_.get(), TCSETS, nullptr),
              SyscallFailsWithErrno(EFAULT));

  // Verify that the termios state is unchanged.
  struct kernel_termios t_after = {};
  ASSERT_THAT(ioctl(replica_.get(), TCGETS, &t_after), SyscallSucceeds());
  EXPECT_EQ(t_after, t);

  // Also test TCSETS2.
  struct kernel_termios2 t2 = {};
  ASSERT_THAT(ioctl(replica_.get(), TCGETS2, &t2), SyscallSucceeds());
  EXPECT_THAT(ioctl(replica_.get(), TCSETS2, nullptr),
              SyscallFailsWithErrno(EFAULT));

  struct kernel_termios2 t2_after = {};
  ASSERT_THAT(ioctl(replica_.get(), TCGETS2, &t2_after), SyscallSucceeds());
  EXPECT_EQ(memcmp(&t2, &t2_after, sizeof(t2)), 0);
}

// Changing termios from the master actually affects the replica.
//
// TCSETS on the master actually redirects to the replica (see comment on
// MasterTermiosUnchangable).
TEST_F(PtyTest, TermiosAffectsReplica) {
  struct kernel_termios master_termios = {};
  EXPECT_THAT(ioctl(master_.get(), TCGETS, &master_termios), SyscallSucceeds());
  master_termios.c_lflag ^= ICANON;
  EXPECT_THAT(ioctl(master_.get(), TCSETS, &master_termios), SyscallSucceeds());

  struct kernel_termios replica_termios = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS, &replica_termios),
              SyscallSucceeds());
  EXPECT_EQ(master_termios, replica_termios);
}

// The master end of the pty has termios:
//
// struct kernel_termios t = {
//   .c_iflag = 0;
//   .c_oflag = 0;
//   .c_cflag = B38400 | CS8 | CREAD;
//   .c_lflag = 0;
//   .c_cc = /* same as DefaultTermios */
// }
//
// (From drivers/tty/pty.c:unix98_pty_init)
//
// All termios control ioctls on the master actually redirect to the replica
// (drivers/tty/tty_ioctl.c:tty_mode_ioctl), making it impossible to change the
// master termios.
//
// Verify this by setting ICRNL (which rewrites input \r to \n) and verify that
// it has no effect on the master.
TEST_F(PtyTest, MasterTermiosUnchangable) {
  struct kernel_termios master_termios = {};
  EXPECT_THAT(ioctl(master_.get(), TCGETS, &master_termios), SyscallSucceeds());
  master_termios.c_lflag |= ICRNL;
  EXPECT_THAT(ioctl(master_.get(), TCSETS, &master_termios), SyscallSucceeds());

  char c = '\r';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(master_, 1, &c);
  EXPECT_EQ(c, '\r');  // ICRNL had no effect!

  ExpectFinished(master_);
}

// ICRNL rewrites input \r to \n.
TEST_F(PtyTest, TermiosICRNL) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= ICRNL;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\r';
  ASSERT_THAT(WriteFd(master_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(replica_, 1, &c);
  EXPECT_EQ(c, '\n');

  ExpectFinished(replica_);
}

// ONLCR rewrites output \n to \r\n.
TEST_F(PtyTest, TermiosONLCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_oflag |= ONLCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\n';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Extra byte for NUL for EXPECT_STREQ.
  char buf[3] = {};
  ExpectReadable(master_, 2, buf);
  EXPECT_STREQ(buf, "\r\n");

  ExpectFinished(replica_);
}

// ICRNL rewrites input \r to \n.
TEST_F(PtyTest, TCSETSFTermiosICRNL) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= ICRNL;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETSF, &t), SyscallSucceeds());

  char c = '\r';
  ASSERT_THAT(WriteFd(master_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(replica_, 1, &c);
  EXPECT_EQ(c, '\n');

  ExpectFinished(replica_);
}

// ONLCR rewrites output \n to \r\n.
TEST_F(PtyTest, TCSETSFTermiosONLCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_oflag |= ONLCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETSF, &t), SyscallSucceeds());

  char c = '\n';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Extra byte for NUL for EXPECT_STREQ.
  char buf[3] = {};
  ExpectReadable(master_, 2, buf);
  EXPECT_STREQ(buf, "\r\n");

  ExpectFinished(replica_);
}

TEST_F(PtyTest, TermiosIGNCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IGNCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\r';
  ASSERT_THAT(WriteFd(master_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Nothing to read.
  ASSERT_THAT(PollAndReadFd(replica_.get(), &c, 1, kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));
}

// Test that we can successfully poll for readable data from the replica.
TEST_F(PtyTest, TermiosPollReplica) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IGNCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  absl::Notification notify;
  int sfd = replica_.get();
  ScopedThread th([sfd, &notify]() {
    notify.Notify();

    // Poll on the reader fd with POLLIN event.
    struct pollfd poll_fd = {sfd, POLLIN, 0};
    EXPECT_THAT(
        RetryEINTR(poll)(&poll_fd, 1, absl::ToInt64Milliseconds(kTimeout)),
        SyscallSucceedsWithValue(1));

    // Should trigger POLLIN event.
    EXPECT_EQ(poll_fd.revents & POLLIN, POLLIN);
  });

  notify.WaitForNotification();
  // Sleep ensures that poll begins waiting before we write to the FD.
  absl::SleepFor(absl::Seconds(1));

  char s[] = "foo\n";
  ASSERT_THAT(WriteFd(master_.get(), s, strlen(s) + 1), SyscallSucceeds());
}

// Test that we can successfully poll for readable data from the master.
TEST_F(PtyTest, TermiosPollMaster) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IGNCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(master_.get(), TCSETS, &t), SyscallSucceeds());

  absl::Notification notify;
  int mfd = master_.get();
  ScopedThread th([mfd, &notify]() {
    notify.Notify();

    // Poll on the reader fd with POLLIN event.
    struct pollfd poll_fd = {mfd, POLLIN, 0};
    EXPECT_THAT(
        RetryEINTR(poll)(&poll_fd, 1, absl::ToInt64Milliseconds(kTimeout)),
        SyscallSucceedsWithValue(1));

    // Should trigger POLLIN event.
    EXPECT_EQ(poll_fd.revents & POLLIN, POLLIN);
  });

  notify.WaitForNotification();
  // Sleep ensures that poll begins waiting before we write to the FD.
  absl::SleepFor(absl::Seconds(1));

  char s[] = "foo\n";
  ASSERT_THAT(WriteFd(replica_.get(), s, strlen(s) + 1), SyscallSucceeds());
}

TEST_F(PtyTest, TermiosINLCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= INLCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\n';
  ASSERT_THAT(WriteFd(master_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(replica_, 1, &c);
  EXPECT_EQ(c, '\r');

  ExpectFinished(replica_);
}

TEST_F(PtyTest, TermiosONOCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_oflag |= ONOCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  // The terminal is at column 0, so there should be no CR to read.
  char c = '\r';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Nothing to read.
  ASSERT_THAT(PollAndReadFd(master_.get(), &c, 1, kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  // This time the column is greater than 0, so we should be able to read the CR
  // out of the other end.
  constexpr char kInput[] = "foo\r";
  constexpr int kInputSize = sizeof(kInput) - 1;
  ASSERT_THAT(WriteFd(replica_.get(), kInput, kInputSize),
              SyscallSucceedsWithValue(kInputSize));

  char buf[kInputSize] = {};
  ExpectReadable(master_, kInputSize, buf);

  EXPECT_EQ(memcmp(buf, kInput, kInputSize), 0);

  ExpectFinished(master_);

  // Terminal should be at column 0 again, so no CR can be read.
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Nothing to read.
  ASSERT_THAT(PollAndReadFd(master_.get(), &c, 1, kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));
}

TEST_F(PtyTest, TermiosOCRNL) {
  struct kernel_termios t = DefaultTermios();
  t.c_oflag |= OCRNL;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  // The terminal is at column 0, so there should be no CR to read.
  char c = '\r';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(master_, 1, &c);
  EXPECT_EQ(c, '\n');

  ExpectFinished(master_);
}

// Tests that VEOL is disabled when we start, and that we can set it to enable
// it.
TEST_F(PtyTest, VEOLTermination) {
  // Write a few bytes ending with '\0', and confirm that we can't read.
  constexpr char kInput[] = "hello";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));
  char buf[sizeof(kInput)] = {};
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(kInput), kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  // Set the EOL character to '=' and write it.
  constexpr char delim = '=';
  struct kernel_termios t = DefaultTermios();
  t.c_cc[VEOL] = delim;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  // Now we can read, as sending EOL caused the line to become available.
  ExpectReadable(replica_, sizeof(kInput), buf);
  EXPECT_EQ(memcmp(buf, kInput, sizeof(kInput)), 0);

  ExpectReadable(replica_, 1, buf);
  EXPECT_EQ(buf[0], '=');

  ExpectFinished(replica_);
}

// Tests that sending "backspace" to the master fd will be handled properly
// in canonical mode
TEST_F(PtyTest, CanonInputBackspace) {
  constexpr char kInput[] = "gvisor\x7f\n";
  constexpr char kExpectedOutput[] = "gviso\n";
  constexpr char kEchoExpectedOutput[] = "gvisor\b \b\r\n";

  TestCanonicalIO(kInput, kExpectedOutput, kEchoExpectedOutput);
}

// one backspace should delete the entire multibyte character when IUTF8 is set
TEST_F(PtyTest, CanonInputBackspaceMultibyteCharacterWithIUTF8) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IUTF8;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  constexpr char kInput[] = "gviso\xc6\xa9\x7f\n";
  constexpr char kExpectedOutput[] = "gviso\n";
  constexpr char kEchoExpectedOutput[] = "gviso\xc6\xa9\b \b\r\n";

  TestCanonicalIO(kInput, kExpectedOutput, kEchoExpectedOutput);
}

// one backspace should only delete one byte in a multibyte character
// if IUTF8 is not set
TEST_F(PtyTest, CanonInputBackspaceMultibyteCharacterWithoutIUTF8) {
  constexpr char kInput[] = "gviso\xc6\xa9\x7f\n";
  constexpr char kExpectedOutput[] = "gviso\xc6\n";
  constexpr char kEchoExpectedOutput[] = "gviso\xc6\xa9\b \b\r\n";

  TestCanonicalIO(kInput, kExpectedOutput, kEchoExpectedOutput);
}

// backspace should not partially delete a multibyte character when IUTF8 is set
TEST_F(PtyTest, CanonInputBackspaceMultibyteCharacterPartialWithIUTF8) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IUTF8;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  constexpr char kInput[] = "\x80\x7f\n";
  constexpr char kExpectedOutput[] = "\x80\n";
  constexpr char kEchoExpectedOutput[] = "\x80\r\n";

  TestCanonicalIO(kInput, kExpectedOutput, kEchoExpectedOutput);
}

// backspace can partially delete a multibyte character when IUTF8 is not set
TEST_F(PtyTest, CanonInputBackspaceMultibyteCharacterPartialWithoutIUTF8) {
  constexpr char kInput[] = "\x80\x7f\n";
  constexpr char kExpectedOutput[] = "\n";
  constexpr char kEchoExpectedOutput[] = "\x80\b \b\r\n";

  TestCanonicalIO(kInput, kExpectedOutput, kEchoExpectedOutput);
}

// ^W, \x17, should erase a word
TEST_F(PtyTest, CanonInputWordErase) {
  constexpr char kInput[] = "hello hi\x17\n";
  constexpr char kExpectedOutput[] = "hello \n";
  constexpr char kEchoExpectedOutput[] = "hello hi\b \b\b \b\r\n";

  TestCanonicalIO(kInput, kExpectedOutput, kEchoExpectedOutput);
}

// Tests that we can write more than the 4096 character limit, then a
// terminating character, then read out just the first 4095 bytes plus the
// terminator.
TEST_F(PtyTest, CanonBigWrite) {
  constexpr int kWriteLen = kMaxLineSize + 4;
  char input[kWriteLen];
  memset(input, 'M', kWriteLen - 1);
  input[kWriteLen - 1] = '\n';
  ASSERT_THAT(WriteFd(master_.get(), input, kWriteLen),
              SyscallSucceedsWithValue(kWriteLen));

  // We can read the line.
  char buf[kMaxLineSize] = {};
  ExpectReadable(replica_, kMaxLineSize, buf);

  ExpectFinished(replica_);
}

// Tests that data written in canonical mode can be read immediately once
// switched to noncanonical mode.
TEST_F(PtyTest, SwitchCanonToNoncanon) {
  // Write a few bytes without a terminating character, switch to noncanonical
  // mode, and read them.
  constexpr char kInput[] = "hello";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));

  // Nothing available yet.
  char buf[sizeof(kInput)] = {};
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(kInput), kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  DisableCanonical();

  ExpectReadable(replica_, sizeof(kInput), buf);
  EXPECT_STREQ(buf, kInput);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchCanonToNonCanonNewline) {
  // Write a few bytes with a terminating character.
  constexpr char kInput[] = "hello\n";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));

  DisableCanonical();

  // We can read the line.
  char buf[sizeof(kInput)] = {};
  ExpectReadable(replica_, sizeof(kInput), buf);
  EXPECT_STREQ(buf, kInput);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonNewlineBig) {
  DisableCanonical();

  // Write more than the maximum line size, then write a delimiter.
  constexpr int kWriteLen = 4100;
  char input[kWriteLen];
  memset(input, 'M', kWriteLen);
  ASSERT_THAT(WriteFd(master_.get(), input, kWriteLen),
              SyscallSucceedsWithValue(kWriteLen));
  // Wait for the input queue to fill.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kMaxLineSize - 1));
  constexpr char delim = '\n';
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  EnableCanonical();

  // We can read the line.
  char buf[kMaxLineSize] = {};
  ExpectReadable(replica_, kMaxLineSize - 1, buf);

  // We can also read the remaining characters.
  ExpectReadable(replica_, 6, buf);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonNoNewline) {
  DisableCanonical();

  // Write a few bytes without a terminating character.
  // mode, and read them.
  constexpr char kInput[] = "hello";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));

  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(kInput) - 1));
  EnableCanonical();

  // We can read the line.
  char buf[sizeof(kInput)] = {};
  ExpectReadable(replica_, sizeof(kInput) - 1, buf);
  EXPECT_STREQ(buf, kInput);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonNoNewlineBig) {
  DisableCanonical();

  // Write a few bytes without a terminating character.
  // mode, and read them.
  constexpr int kWriteLen = 4100;
  char input[kWriteLen];
  memset(input, 'M', kWriteLen);
  ASSERT_THAT(WriteFd(master_.get(), input, kWriteLen),
              SyscallSucceedsWithValue(kWriteLen));

  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kMaxLineSize - 1));
  EnableCanonical();

  // We can read the line.
  char buf[kMaxLineSize] = {};
  ExpectReadable(replica_, kMaxLineSize - 1, buf);

  ExpectFinished(replica_);
}

// If the canonical input buffer is empty, and we switch to non-canonical
// mode, the input buffer should not be readable.
TEST_F(PtyTest, SwitchCanonToNoncanonEmptyInput) {
  constexpr char kInput[] = "";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));

  DisableCanonical();

  // Nothing available yet.
  char buf[2] = {};
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, 2, kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  ExpectFinished(replica_);
}

// Tests that we can write over the 4095 noncanonical limit, then read out
// everything.
TEST_F(PtyTest, NoncanonBigWrite) {
  DisableCanonical();

  // Write well over the 4095 internal buffer limit.
  constexpr char kInput = 'M';
  constexpr int kInputSize = kMaxLineSize * 2;
  for (int i = 0; i < kInputSize; i++) {
    // This makes too many syscalls for save/restore.
    const DisableSave ds;
    ASSERT_THAT(WriteFd(master_.get(), &kInput, sizeof(kInput)),
                SyscallSucceedsWithValue(sizeof(kInput)));
  }

  // We should be able to read out everything. Sleep a bit so that Linux has a
  // chance to move data from the master to the replica.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kMaxLineSize - 1));
  for (int i = 0; i < kInputSize; i++) {
    // This makes too many syscalls for save/restore.
    const DisableSave ds;
    char c;
    ExpectReadable(replica_, 1, &c);
    ASSERT_EQ(c, kInput);
  }

  ExpectFinished(replica_);
}

// ICANON doesn't make input available until a line delimiter is typed.
//
// Test newline.
TEST_F(PtyTest, TermiosICANONNewline) {
  char input[3] = {'a', 'b', 'c'};
  ASSERT_THAT(WriteFd(master_.get(), input, sizeof(input)),
              SyscallSucceedsWithValue(sizeof(input)));

  // Extra bytes for newline (written later) and NUL for EXPECT_STREQ.
  char buf[5] = {};

  // Nothing available yet.
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(input), kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  char delim = '\n';
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  // Now it is available.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(input) + 1));
  ExpectReadable(replica_, sizeof(input) + 1, buf);
  EXPECT_STREQ(buf, "abc\n");

  ExpectFinished(replica_);
}

// ICANON doesn't make input available until a line delimiter is typed.
//
// Test EOF (^D).
TEST_F(PtyTest, TermiosICANONEOF) {
  char input[3] = {'a', 'b', 'c'};
  ASSERT_THAT(WriteFd(master_.get(), input, sizeof(input)),
              SyscallSucceedsWithValue(sizeof(input)));

  // Extra byte for NUL for EXPECT_STREQ.
  char buf[4] = {};

  // Nothing available yet.
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(input), kTimeoutShort),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));
  char delim = ControlCharacter('D');
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  // Now it is available. Note that ^D is not included.
  ExpectReadable(replica_, sizeof(input), buf);
  EXPECT_STREQ(buf, "abc");

  // New Linux kernels can return zero.
  EXPECT_THAT(
      ReadFd(replica_.get(), buf, 1),
      AnyOf(SyscallSucceedsWithValue(0), SyscallFailsWithErrno(EAGAIN)));
}

// ICANON limits us to 4096 bytes including a terminating character. Anything
// after and 4095th character is discarded (although still processed for
// signals and echoing).
TEST_F(PtyTest, CanonDiscard) {
  constexpr char kInput = 'M';
  constexpr int kInputSize = 4100;
  constexpr int kIter = 3;

  // A few times write more than the 4096 character maximum, then a newline.
  constexpr char delim = '\n';
  for (int i = 0; i < kIter; i++) {
    // This makes too many syscalls for save/restore.
    const DisableSave ds;
    for (int i = 0; i < kInputSize; i++) {
      ASSERT_THAT(WriteFd(master_.get(), &kInput, sizeof(kInput)),
                  SyscallSucceedsWithValue(sizeof(kInput)));
    }
    ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));
  }

  // There should be multiple truncated lines available to read.
  for (int i = 0; i < kIter; i++) {
    char buf[kInputSize] = {};
    ExpectReadable(replica_, kMaxLineSize, buf);
    EXPECT_EQ(buf[kMaxLineSize - 1], delim);
    EXPECT_EQ(buf[kMaxLineSize - 2], kInput);
  }

  ExpectFinished(replica_);
}

TEST_F(PtyTest, CanonMultiline) {
  constexpr char kInput1[] = "GO\n";
  constexpr char kInput2[] = "BLUE\n";

  // Write both lines.
  ASSERT_THAT(WriteFd(master_.get(), kInput1, sizeof(kInput1) - 1),
              SyscallSucceedsWithValue(sizeof(kInput1) - 1));
  ASSERT_THAT(WriteFd(master_.get(), kInput2, sizeof(kInput2) - 1),
              SyscallSucceedsWithValue(sizeof(kInput2) - 1));

  // Get the first line.
  char line1[8] = {};
  ExpectReadable(replica_, sizeof(kInput1) - 1, line1);
  EXPECT_STREQ(line1, kInput1);

  // Get the second line.
  char line2[8] = {};
  ExpectReadable(replica_, sizeof(kInput2) - 1, line2);
  EXPECT_STREQ(line2, kInput2);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonMultiline) {
  DisableCanonical();

  constexpr char kInput1[] = "GO\n";
  constexpr char kInput2[] = "BLUE\n";
  constexpr char kExpected[] = "GO\nBLUE\n";

  // Write both lines.
  ASSERT_THAT(WriteFd(master_.get(), kInput1, sizeof(kInput1) - 1),
              SyscallSucceedsWithValue(sizeof(kInput1) - 1));
  ASSERT_THAT(WriteFd(master_.get(), kInput2, sizeof(kInput2) - 1),
              SyscallSucceedsWithValue(sizeof(kInput2) - 1));

  ASSERT_NO_ERRNO(
      WaitUntilReceived(replica_.get(), sizeof(kInput1) + sizeof(kInput2) - 2));
  EnableCanonical();

  // Get all together as one line.
  char line[9] = {};
  ExpectReadable(replica_, 8, line);
  EXPECT_STREQ(line, kExpected);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchTwiceMultiline) {
  std::string kInputs[] = {"GO\n", "BLUE\n", "!"};
  std::string kExpected = "GO\nBLUE\n!";

  // Write each line.
  for (const std::string &input : kInputs) {
    ASSERT_THAT(WriteFd(master_.get(), input.c_str(), input.size()),
                SyscallSucceedsWithValue(input.size()));
  }

  DisableCanonical();
  // All written characters have to make it into the input queue before
  // canonical mode is re-enabled. If the final '!' character hasn't been
  // enqueued before canonical mode is re-enabled, it won't be readable.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kExpected.size()));
  EnableCanonical();

  // Get all together as one line.
  char line[10] = {};
  ExpectReadable(replica_, 9, line);
  EXPECT_STREQ(line, kExpected.c_str());

  ExpectFinished(replica_);
}

TEST_F(PtyTest, QueueSize) {
  // Write the line.
  constexpr char kInput1[] = "GO\n";
  ASSERT_THAT(WriteFd(master_.get(), kInput1, sizeof(kInput1) - 1),
              SyscallSucceedsWithValue(sizeof(kInput1) - 1));
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(kInput1) - 1));

  // Ensure that writing more (beyond what is readable) does not impact the
  // readable size.
  char input[kMaxLineSize];
  memset(input, 'M', kMaxLineSize);
  ASSERT_THAT(WriteFd(master_.get(), input, kMaxLineSize),
              SyscallSucceedsWithValue(kMaxLineSize));
  int inputBufSize = ASSERT_NO_ERRNO_AND_VALUE(
      WaitUntilReceived(replica_.get(), sizeof(kInput1) - 1));
  EXPECT_EQ(inputBufSize, sizeof(kInput1) - 1);
}

TEST_F(PtyTest, PartialBadBuffer) {
  // Allocate 2 pages.
  void *addr = mmap(nullptr, 2 * kPageSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(addr, MAP_FAILED);
  char *buf = reinterpret_cast<char *>(addr);

  // Guard the 2nd page for our read to run into.
  ASSERT_THAT(
      mprotect(reinterpret_cast<void *>(buf + kPageSize), kPageSize, PROT_NONE),
      SyscallSucceeds());

  // Leave only one free byte in the buffer.
  char *bad_buffer = buf + kPageSize - 1;

  // Write to the master.
  constexpr char kBuf[] = "hello\n";
  constexpr size_t size = sizeof(kBuf) - 1;
  EXPECT_THAT(WriteFd(master_.get(), kBuf, size),
              SyscallSucceedsWithValue(size));

  // Read from the replica into bad_buffer.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), size));
  // Before Linux 3b830a9c this returned EFAULT, but after that commit it
  // returns EAGAIN.
  EXPECT_THAT(
      ReadFd(replica_.get(), bad_buffer, size),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallFailsWithErrno(EAGAIN)));

  EXPECT_THAT(munmap(addr, 2 * kPageSize), SyscallSucceeds()) << addr;
}

// Test that writing nothing to the PTY replica's output queue does not return
// an error.
TEST_F(PtyTest, ReplicaWriteNothingCanonical) {
  constexpr char kInput[] = "";
  EXPECT_THAT(WriteFd(replica_.get(), kInput, strlen(kInput)),
              SyscallSucceedsWithValue(strlen(kInput)));

  ExpectFinished(master_);
}

TEST_F(PtyTest, ReplicaWriteNothingNonCanonical) {
  DisableCanonical();

  constexpr char kInput[] = "";
  EXPECT_THAT(WriteFd(replica_.get(), kInput, strlen(kInput)),
              SyscallSucceedsWithValue(strlen(kInput)));

  ExpectFinished(master_);
}

TEST_F(PtyTest, SimpleEcho) {
  constexpr char kInput[] = "Mr. Eko";
  EXPECT_THAT(WriteFd(master_.get(), kInput, strlen(kInput)),
              SyscallSucceedsWithValue(strlen(kInput)));

  char buf[100] = {};
  ExpectReadable(master_, strlen(kInput), buf);

  EXPECT_STREQ(buf, kInput);
  ExpectFinished(master_);
}

// Verifies that fd reads back exactly expected, and nothing after it.
void ExpectEcho(const FileDescriptor& fd, const std::string& expected) {
  std::string buf(expected.size(), '\0');
  ExpectReadable(fd, expected.size(), &buf[0]);
  EXPECT_EQ(buf, expected);
  ExpectFinished(fd);
}

// A character that ISIG turns into a signal by default, the signal, and how
// it is echoed with ECHOCTL.
struct SignalChar {
  char input;
  int signal;
  const char* echo;
};

constexpr SignalChar kSignalChars[] = {
    {ControlCharacter('C'), SIGINT, "^C"},
    {ControlCharacter('\\'), SIGQUIT, "^\\"},
    {ControlCharacter('Z'), SIGTSTP, "^Z"},
};

// With ECHO and ECHOCTL, as by default, a signal character is echoed as ^X
// and is not passed to the reader. This matches
// n_tty.c:n_tty_receive_signal_char().
TEST_F(PtyTest, SignalCharEchoedWithECHOCTL) {
  for (const SignalChar& sc : kSignalChars) {
    ASSERT_THAT(WriteFd(master_.get(), &sc.input, 1),
                SyscallSucceedsWithValue(1));
    ExpectEcho(master_, sc.echo);
  }

  // None of the signal characters is part of the next line.
  TestCanonicalIO("a\n", "a\n", "a\r\n");
}

// Without ECHOCTL, a signal character is echoed as is.
TEST_F(PtyTest, SignalCharEchoedWithoutECHOCTL) {
  struct kernel_termios t = DefaultTermios();
  t.c_lflag &= ~ECHOCTL;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  for (const SignalChar& sc : kSignalChars) {
    ASSERT_THAT(WriteFd(master_.get(), &sc.input, 1),
                SyscallSucceedsWithValue(1));
    ExpectEcho(master_, std::string(1, sc.input));
  }
}

// Without ECHO, a signal character is not echoed.
TEST_F(PtyTest, SignalCharNotEchoedWithoutECHO) {
  struct kernel_termios t = DefaultTermios();
  t.c_lflag &= ~ECHO;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  // The line becomes readable only after the signal character before it has
  // been processed.
  constexpr char kInput[] = {ControlCharacter('C'), 'a', '\n'};
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));
  char buf[3] = {};
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), 2));
  ExpectReadable(replica_, 2, buf);
  EXPECT_STREQ(buf, "a\n");
  ExpectFinished(master_);
}

// With ECHOCTL, a control character in a line is echoed as ^X, except TAB and
// the newline that ends the line, and reaches the reader unchanged.
TEST_F(PtyTest, ControlCharEchoedWithECHOCTL) {
  TestCanonicalIO("a\x01\x1b\tb\n", "a\x01\x1b\tb\n", "a^A^[\tb\r\n");
}

// Without ECHOCTL, a control character is echoed as is.
TEST_F(PtyTest, ControlCharEchoedWithoutECHOCTL) {
  struct kernel_termios t = DefaultTermios();
  t.c_lflag &= ~ECHOCTL;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  TestCanonicalIO("a\x01" "b\n", "a\x01" "b\n", "a\x01" "b\r\n");
}

// In noncanonical mode, a newline is echoed as ^J with ECHOCTL, but a
// carriage return that ICRNL turns into a newline is echoed as a newline.
TEST_F(PtyTest, NoncanonNewlineEchoedWithECHOCTL) {
  DisableCanonical();

  constexpr char kCR = '\r';
  ASSERT_THAT(WriteFd(master_.get(), &kCR, 1), SyscallSucceedsWithValue(1));
  ExpectEcho(master_, "\r\n");

  constexpr char kNL = '\n';
  ASSERT_THAT(WriteFd(master_.get(), &kNL, 1), SyscallSucceedsWithValue(1));
  ExpectEcho(master_, "^J");

  char buf[3] = {};
  ExpectReadable(replica_, 2, buf);
  EXPECT_STREQ(buf, "\n\n");
  ExpectFinished(replica_);
}

// With IXON, START and STOP are flow control characters, which are never
// echoed.
TEST_F(PtyTest, FlowControlCharsNotEchoedWithIXON) {
  constexpr char kInput[] = {ControlCharacter('S'), ControlCharacter('Q'), 'x'};
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));
  ExpectEcho(master_, "x");
}

// Verifies that fd reads back exactly expected, which may contain NUL bytes,
// and nothing after it.
void ExpectReadExactly(const FileDescriptor& fd, const std::string& expected) {
  std::string buf(expected.size(), 'x');
  ExpectReadable(fd, expected.size(), &buf[0]);
  EXPECT_EQ(buf, expected);
  ExpectFinished(fd);
}

// Writes input to fd, which may contain NUL bytes.
void WriteAll(const FileDescriptor& fd, const std::string& input) {
  ASSERT_THAT(WriteFd(fd.get(), input.data(), input.size()),
              SyscallSucceedsWithValue(input.size()));
}

// A control character set to _POSIX_VDISABLE (0) matches no input, so a NUL
// byte is an ordinary character even when VINTR is disabled. This matches
// n_tty.c:n_tty_set_termios(), which never maps __DISABLED_CHAR.
TEST_F(PtyTest, DisabledCharSignalIsOrdinary) {
  struct kernel_termios t = DefaultTermios();
  t.c_lflag &= ~ICANON;
  t.c_cc[VINTR] = _POSIX_VDISABLE;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  WriteAll(master_, std::string(1, '\0'));
  ExpectEcho(master_, "^@");
  ExpectReadExactly(replica_, std::string(1, '\0'));
}

// The same holds for every special character in canonical mode.
TEST_F(PtyTest, DisabledCharsAreOrdinary) {
  struct kernel_termios t = DefaultTermios();
  for (int cc : {VINTR, VQUIT, VSUSP, VERASE, VKILL, VWERASE, VLNEXT, VREPRINT,
                 VSTART, VSTOP}) {
    t.c_cc[cc] = _POSIX_VDISABLE;
  }
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  const std::string line("a\0b\n", 4);
  WriteAll(master_, line);
  ExpectEcho(master_, "a^@b\r\n");
  ExpectReadExactly(replica_, line);
}

// Unless NOFLSH is set, a signal character discards the input typed before
// it, as n_tty.c:isig() does.
TEST_F(PtyTest, SignalCharFlushesInput) {
  WriteAll(master_, "abc");
  ExpectEcho(master_, "abc");
  WriteAll(master_, std::string(1, ControlCharacter('C')));
  ExpectEcho(master_, "^C");
  TestCanonicalIO("\n", "\n", "\r\n");
}

// With NOFLSH, the input typed before a signal character is kept.
TEST_F(PtyTest, SignalCharFlushSkippedWithNOFLSH) {
  struct kernel_termios t = DefaultTermios();
  t.c_lflag |= NOFLSH;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  WriteAll(master_, "abc");
  ExpectEcho(master_, "abc");
  WriteAll(master_, std::string(1, ControlCharacter('C')));
  ExpectEcho(master_, "^C");
  TestCanonicalIO("\n", "abc\n", "\r\n");
}

// The flush also discards the echoes not written to the terminal yet: those of
// the input written along with the signal character, including the echo of an
// earlier signal character.
TEST_F(PtyTest, SignalCharFlushDiscardsPendingEchoes) {
  TestCanonicalIO("abc\x03\n", "\n", "^C\r\n");
  TestCanonicalIO(
      "ab\x1c"
      "c\x1a"
      "d\n",
      "d\n", "^Zd\r\n");
}

// In noncanonical mode, the flush discards all the input not read yet.
TEST_F(PtyTest, SignalCharFlushesNoncanonicalInput) {
  DisableCanonical();

  WriteAll(master_, "abc");
  ExpectEcho(master_, "abc");
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), 3));
  WriteAll(master_, std::string(1, ControlCharacter('C')));
  ExpectEcho(master_, "^C");
  ExpectFinished(replica_);
}

// A packet mode master is told about the flush.
TEST_F(PtyTest, SignalCharFlushReportsPacketModeStatus) {
  EnablePacketMode();

  WriteAll(master_, "abc");
  ExpectEcho(master_, std::string("\0abc", 4));
  WriteAll(master_, std::string(1, ControlCharacter('C')));
  ExpectMasterPacketStatus(TIOCPKT_FLUSHREAD | TIOCPKT_FLUSHWRITE);
  ExpectEcho(master_, std::string("\0^C", 3));
}

// Sets the replica to the default termios with the given local flags set and
// cleared.
void SetLocalFlags(const FileDescriptor& replica, tcflag_t set,
                   tcflag_t clear) {
  struct kernel_termios t = DefaultTermios();
  t.c_lflag |= set;
  t.c_lflag &= ~clear;
  ASSERT_THAT(ioctl(replica.get(), TCSETS, &t), SyscallSucceeds());
}

// Types "abc" and the kill character, and checks the kill character's echo.
void TypeLineAndKill(const FileDescriptor& master, const std::string& echo) {
  WriteAll(master, "abc");
  ExpectEcho(master, "abc");
  WriteAll(master, std::string(1, ControlCharacter('U')));
  ExpectEcho(master, echo);
}

// With ECHOK, ECHOKE and ECHOE, as by default, the kill character erases the
// line typed so far and each of its characters from the screen. This matches
// n_tty.c:eraser().
TEST_F(PtyTest, KillCharErasesLine) {
  TypeLineAndKill(master_, "\b \b\b \b\b \b");
  TestCanonicalIO("def\n", "def\n", "def\r\n");
}

// Without ECHOKE, the line is erased and the kill character echoed, followed
// by a newline with ECHOK.
TEST_F(PtyTest, KillCharWithoutECHOKE) {
  SetLocalFlags(replica_, 0, ECHOKE);
  TypeLineAndKill(master_, "^U\r\n");
  TestCanonicalIO("def\n", "def\n", "def\r\n");
}

// Without ECHOK either, only the kill character is echoed.
TEST_F(PtyTest, KillCharWithoutECHOKAndECHOKE) {
  SetLocalFlags(replica_, 0, ECHOK | ECHOKE);
  TypeLineAndKill(master_, "^U");
  TestCanonicalIO("def\n", "def\n", "def\r\n");
}

// Without ECHO, the line is erased silently.
TEST_F(PtyTest, KillCharWithoutECHO) {
  SetLocalFlags(replica_, 0, ECHO);
  WriteAll(master_,
           "abc\x15"
           "def\n");
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), 4));
  ExpectReadExactly(replica_, "def\n");
  ExpectFinished(master_);
}

// On an empty line, the kill character does nothing, not even echo.
TEST_F(PtyTest, KillCharOnEmptyLine) {
  SetLocalFlags(replica_, 0, ECHOKE);
  WriteAll(master_, std::string(1, ControlCharacter('U')));
  TestCanonicalIO("def\n", "def\n", "def\r\n");
}

// A control character shown as ^X is erased from the screen as two columns.
TEST_F(PtyTest, KillCharErasesControlChars) {
  WriteAll(master_,
           "a\x01"
           "b");
  ExpectEcho(master_, "a^Ab");
  WriteAll(master_, std::string(1, ControlCharacter('U')));
  ExpectEcho(master_, "\b \b\b \b\b \b\b \b");
}

// In noncanonical mode, the kill character is an ordinary character.
TEST_F(PtyTest, KillCharInNoncanonicalMode) {
  DisableCanonical();
  WriteAll(master_, "a\x15");
  ExpectEcho(master_, "a^U");
  ExpectReadExactly(replica_, "a\x15");
}

// Without ECHOE, the erase character is echoed rather than erasing the
// character from the screen.
TEST_F(PtyTest, EraseCharWithoutECHOE) {
  SetLocalFlags(replica_, 0, ECHOE);
  WriteAll(master_, "ab");
  ExpectEcho(master_, "ab");
  WriteAll(master_, "\x7f");
  ExpectEcho(master_, "^?");
  TestCanonicalIO("\n", "a\n", "\r\n");
}

// The character after VLNEXT is queued as is, even a signal character, as
// n_tty.c:n_tty_receive_char_lnext() does. With ECHOCTL, "^\b" is echoed in
// its place until it arrives.
TEST_F(PtyTest, LiteralNextQueuesSignalChar) {
  TestCanonicalIO("\x16\x03\n", "\x03\n", "^\b^C\r\n");
}

// VLNEXT applies to the next character even when it is written separately.
TEST_F(PtyTest, LiteralNextAcrossWrites) {
  WriteAll(master_, "\x16");
  ExpectEcho(master_, "^\b");
  TestCanonicalIO("\x03\n", "\x03\n", "^C\r\n");
}

// An erase character after VLNEXT is queued rather than erasing.
TEST_F(PtyTest, LiteralNextQueuesEraseChar) {
  TestCanonicalIO("a\x16\x7f\n", "a\x7f\n", "a^\b^?\r\n");
}

// A newline after VLNEXT does not end the line.
TEST_F(PtyTest, LiteralNextNewlineDoesNotEndLine) {
  WriteAll(master_, "a\x16\nb\n");
  ExpectEcho(master_, "a^\b^Jb\r\n");
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), 4));
  // One read returns the whole line. (ReadFd would read again for the rest
  // of the buffer.)
  char buf[8] = {};
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(4));
  EXPECT_STREQ(buf, "a\nb\n");
}

// VREPRINT echoes itself, a newline and the line typed so far.
TEST_F(PtyTest, ReprintCharReprintsLine) {
  WriteAll(master_, "a\x01");
  ExpectEcho(master_, "a^A");
  WriteAll(master_, "\x12");
  ExpectEcho(master_, "^R\r\na^A");
  TestCanonicalIO("\n", "a\x01\n", "\r\n");
}

// With ECHONL, a newline is echoed in canonical mode even without ECHO.
TEST_F(PtyTest, EchoNLWithoutECHO) {
  SetLocalFlags(replica_, ECHONL, ECHO);
  TestCanonicalIO("ab\n", "ab\n", "\r\n");
}

// In noncanonical mode, VLNEXT and VREPRINT are ordinary characters.
TEST_F(PtyTest, LiteralNextAndReprintCharInNoncanonicalMode) {
  DisableCanonical();
  WriteAll(master_, "\x16\x12");
  ExpectEcho(master_, "^V^R");
  ExpectReadExactly(replica_, "\x16\x12");
}

// Waits until poll reports fd writable, or not writable, as want says.
PosixError WaitUntilWritable(int fd, bool want) {
  absl::Time end = absl::Now() + kTimeout;
  while (absl::Now() < end) {
    struct pollfd pfd = {fd, POLLOUT, 0};
    int ret = RetryEINTR(poll)(&pfd, 1, 0);
    if (ret < 0) {
      return PosixError(errno, "poll failed");
    }
    if ((ret == 1) == want) {
      return NoError();
    }
    absl::SleepFor(absl::Milliseconds(10));
  }
  return PosixError(ETIMEDOUT, want ? "never writable" : "still writable");
}

// Types VSTOP and waits until output is stopped.
void StopOutput(const FileDescriptor& master, const FileDescriptor& replica) {
  WriteAll(master, std::string(1, ControlCharacter('S')));
  ASSERT_NO_ERRNO(WaitUntilWritable(replica.get(), false));
}

// With IXON, as by default, VSTOP stops output from the replica and VSTART
// starts it again, as tty_io.c:stop_tty() and start_tty() do. While output is
// stopped, the replica is not writable and cannot write (pty.c:pty_write()).
TEST_F(PtyTest, StopCharHoldsOutput) {
  StopOutput(master_, replica_);
  char c = 'x';
  EXPECT_THAT(WriteFd(replica_.get(), &c, 1), SyscallFailsWithErrno(EAGAIN));
  ExpectFinished(master_);

  WriteAll(master_, std::string(1, ControlCharacter('Q')));
  ASSERT_NO_ERRNO(WaitUntilWritable(replica_.get(), true));
  WriteAll(replica_, "out");
  ExpectEcho(master_, "out");
}

// A blocking write waits for output to start.
TEST_F(PtyTest, StopCharBlocksWriter) {
  FileDescriptor replica =
      ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master_, O_RDWR | O_NOCTTY));
  StopOutput(master_, replica_);

  absl::Notification written;
  int fd = replica.get();
  ScopedThread th([fd, &written]() {
    EXPECT_THAT(WriteFd(fd, "out", 3), SyscallSucceedsWithValue(3));
    written.Notify();
  });
  EXPECT_FALSE(written.WaitForNotificationWithTimeout(absl::Seconds(1)));
  WriteAll(master_, std::string(1, ControlCharacter('Q')));
  EXPECT_TRUE(written.WaitForNotificationWithTimeout(kTimeout));
  th.Join();
  ExpectEcho(master_, "out");
}

// While output is stopped, the echoes of input wait too, but the input reaches
// the reader.
TEST_F(PtyTest, StopCharHoldsEchoes) {
  DisableCanonical();
  WriteAll(master_,
           "\x13"
           "ab");
  ExpectReadExactly(replica_, "ab");
  ExpectFinished(master_);

  WriteAll(master_, "\x11");
  ExpectEcho(master_, "ab");
}

// VSTOP and VSTART are not passed to the reader.
TEST_F(PtyTest, StopCharAndStartCharAreNotRead) {
  TestCanonicalIO(
      "\x13\x11"
      "a\n",
      "a\n", "a\r\n");
}

// Without IXON, they are ordinary characters.
TEST_F(PtyTest, StopCharWithoutIXONIsOrdinary) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag &= ~IXON;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  TestCanonicalIO(
      "\x13\x11"
      "a\n",
      "\x13\x11"
      "a\n",
      "^S^Qa\r\n");
}

// A packet mode master is told TIOCPKT_STOP and TIOCPKT_START, each of which
// replaces the other (pty.c:pty_stop() and pty_start()).
TEST_F(PtyTest, StopCharReportsPacketModeStatus) {
  EnablePacketMode();

  WriteAll(master_, std::string(1, ControlCharacter('S')));
  ExpectMasterPacketStatus(TIOCPKT_STOP);
  WriteAll(master_, std::string(1, ControlCharacter('Q')));
  ExpectMasterPacketStatus(TIOCPKT_START);
  WriteAll(master_, "\x13\x11");
  ExpectMasterPacketStatus(TIOCPKT_START);
}

// With IXANY, any input character starts output again.
TEST_F(PtyTest, StopCharThenIXANYRestarts) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IXANY;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  StopOutput(master_, replica_);
  WriteAll(master_, "x");
  ExpectEcho(master_, "x");
  ASSERT_NO_ERRNO(WaitUntilWritable(replica_.get(), true));
}

// A signal character starts output again.
TEST_F(PtyTest, StopCharThenSignalCharRestarts) {
  StopOutput(master_, replica_);
  WriteAll(master_, std::string(1, ControlCharacter('C')));
  ExpectEcho(master_, "^C");
  ASSERT_NO_ERRNO(WaitUntilWritable(replica_.get(), true));
}

// Turning IXON off starts output again.
TEST_F(PtyTest, StopCharThenClearingIXONRestarts) {
  StopOutput(master_, replica_);
  struct kernel_termios t = DefaultTermios();
  t.c_iflag &= ~IXON;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  ASSERT_NO_ERRNO(WaitUntilWritable(replica_.get(), true));
  WriteAll(replica_, "out");
  ExpectEcho(master_, "out");
}

// Input typed ahead while complete lines wait unread in canonical mode is
// echoed immediately, FIONREAD counts only completed lines, and each read
// returns one line at a time.
TEST_F(PtyTest, TypeaheadEchoAndReadPerLine) {
  WriteAll(master_, "ab\ncd\nef");
  ExpectEcho(master_, "ab\r\ncd\r\nef");

  int buffered = -1;
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 6);

  char buf[16] = {};
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(3));
  EXPECT_EQ(std::string(buf, 3), "ab\n");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 3);

  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(3));
  EXPECT_EQ(std::string(buf, 3), "cd\n");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 0);
  ExpectFinished(replica_);

  WriteAll(master_, "\n");
  ExpectEcho(master_, "\r\n");
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), 3));
  ExpectReadExactly(replica_, "ef\n");
}

// A partial read of the first queued canonical line leaves the rest of that
// line for the next read without merging it with the following line.
TEST_F(PtyTest, TypeaheadPartialReadAndFIONREAD) {
  WriteAll(master_, "hello\nworld\n");
  ExpectEcho(master_, "hello\r\nworld\r\n");

  int buffered = -1;
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 12);

  char buf[16] = {};
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, 2),
              SyscallSucceedsWithValue(2));
  EXPECT_EQ(std::string(buf, 2), "he");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 10);

  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(4));
  EXPECT_EQ(std::string(buf, 4), "llo\n");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 6);

  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(6));
  EXPECT_EQ(std::string(buf, 6), "world\n");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 0);
  ExpectFinished(replica_);
}

// Ctrl-C after an unread complete line and a partial line echoes immediately
// and flushes every queued line.
TEST_F(PtyTest, TypeaheadSignalFlushesAllLines) {
  WriteAll(master_, "ls\n");
  ExpectEcho(master_, "ls\r\n");
  WriteAll(master_, "ab");
  ExpectEcho(master_, "ab");
  WriteAll(master_, std::string(1, ControlCharacter('C')));
  ExpectEcho(master_, "^C");
  ExpectFinished(replica_);
}

// VSTOP typed after an unread complete line stops output at once rather than
// waiting for the line to be read.
TEST_F(PtyTest, TypeaheadStopCharHoldsOutput) {
  WriteAll(master_, "line1\n");
  ExpectEcho(master_, "line1\r\n");
  WriteAll(master_, "ab\x13");
  ASSERT_NO_ERRNO(WaitUntilWritable(replica_.get(), false));
  ExpectFinished(master_);

  WriteAll(master_, "\x11" "c\n");
  ASSERT_NO_ERRNO(WaitUntilWritable(replica_.get(), true));
  ExpectEcho(master_, "abc\r\n");

  char buf[16] = {};
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(6));
  EXPECT_EQ(std::string(buf, 6), "line1\n");
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(4));
  EXPECT_EQ(std::string(buf, 4), "abc\n");
  ExpectFinished(replica_);
}

// VEOF between lines ends the preceding line without storing the EOF byte,
// and an empty EOF produces a zero-byte read between lines.
TEST_F(PtyTest, TypeaheadEOFBetweenLines) {
  WriteAll(master_, "ab\x04" "cd\n\x04" "ef\n");
  ExpectEcho(master_, "abcd\r\nef\r\n");

  int buffered = -1;
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 8);

  char buf[16] = {};
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(2));
  EXPECT_EQ(std::string(buf, 2), "ab");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 6);

  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(3));
  EXPECT_EQ(std::string(buf, 3), "cd\n");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 3);

  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 3);

  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(3));
  EXPECT_EQ(std::string(buf, 3), "ef\n");
  ASSERT_THAT(ioctl(replica_.get(), FIONREAD, &buffered), SyscallSucceeds());
  EXPECT_EQ(buffered, 0);
  ExpectFinished(replica_);
}

// VERASE, VKILL, and VREPRINT stay within the current line and never touch an
// unread completed line ahead of it.
TEST_F(PtyTest, TypeaheadEditBoundedToCurrentLine) {
  WriteAll(master_, "ab\ncd\x7f\x7f\x7f\x15\x12" "e\n");
  ExpectEcho(master_, "ab\r\ncd\b \b\b \b^R\r\ne\r\n");

  char buf[16] = {};
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(3));
  EXPECT_EQ(std::string(buf, 3), "ab\n");
  ASSERT_THAT(RetryEINTR(read)(replica_.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(2));
  EXPECT_EQ(std::string(buf, 2), "e\n");
  ExpectFinished(replica_);
}

TEST_F(PtyTest, GetWindowSize) {
  struct winsize ws;
  ASSERT_THAT(ioctl(replica_.get(), TIOCGWINSZ, &ws), SyscallSucceeds());
  EXPECT_EQ(ws.ws_row, 0);
  EXPECT_EQ(ws.ws_col, 0);
}

TEST_F(PtyTest, SetReplicaWindowSize) {
  constexpr uint16_t kRows = 343;
  constexpr uint16_t kCols = 2401;
  struct winsize ws = {.ws_row = kRows, .ws_col = kCols};
  ASSERT_THAT(ioctl(replica_.get(), TIOCSWINSZ, &ws), SyscallSucceeds());

  struct winsize retrieved_ws = {};
  ASSERT_THAT(ioctl(master_.get(), TIOCGWINSZ, &retrieved_ws),
              SyscallSucceeds());
  EXPECT_EQ(retrieved_ws.ws_row, kRows);
  EXPECT_EQ(retrieved_ws.ws_col, kCols);
}

TEST_F(PtyTest, SetMasterWindowSize) {
  constexpr uint16_t kRows = 343;
  constexpr uint16_t kCols = 2401;
  struct winsize ws = {.ws_row = kRows, .ws_col = kCols};
  ASSERT_THAT(ioctl(master_.get(), TIOCSWINSZ, &ws), SyscallSucceeds());

  struct winsize retrieved_ws = {};
  ASSERT_THAT(ioctl(replica_.get(), TIOCGWINSZ, &retrieved_ws),
              SyscallSucceeds());
  EXPECT_EQ(retrieved_ws.ws_row, kRows);
  EXPECT_EQ(retrieved_ws.ws_col, kCols);
}

class JobControlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    master_ = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR | O_NONBLOCK));
    replica_ = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master_));

    // Make this a session leader, which also drops the controlling terminal.
    // In the gVisor test environment, this test will be run as the session
    // leader already (as the sentry init process).
    if (!IsRunningOnGvisor()) {
      // Ignore failure because setsid(2) fails if the process is already the
      // session leader.
      setsid();
      ioctl(replica_.get(), TIOCNOTTY);
    }
  }

  PosixError RunInChild(SubprocessCallback childFunc) {
    pid_t child = fork();
    if (!child) {
      childFunc();
      _exit(0);
    }
    int wstatus;
    if (waitpid(child, &wstatus, 0) != child) {
      return PosixError(
          errno, absl::StrCat("child failed with wait status: ", wstatus));
    }
    return PosixError(wstatus, "process returned");
  }

  // Master and replica ends of the PTY. Non-blocking.
  FileDescriptor master_;
  FileDescriptor replica_;
};

TEST_F(JobControlTest, SetTTYMaster) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(master_.get(), TIOCSCTTY, 0));
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTY) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);
    // The second attempt setting the same terminal has to be no-op.
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTYNonLeader) {
  // Fork a process that won't be the session leader.
  auto res =
      RunInChild([=]() { TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0)); });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTYBadArg) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 1));
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTYDifferentSession) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 1));

    // Fork, join a new session, and try to steal the parent's controlling
    // terminal, which should fail.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(setsid() >= 0);
      // We shouldn't be able to steal the terminal.
      TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 1));
      _exit(0);
    }

    int gcwstatus;
    TEST_PCHECK(waitpid(grandchild, &gcwstatus, 0) == grandchild);
    TEST_PCHECK(gcwstatus == 0);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, ReleaseTTY) {
  ASSERT_THAT(ioctl(replica_.get(), TIOCSCTTY, 0), SyscallSucceeds());

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  struct sigaction old_sa;
  EXPECT_THAT(sigaction(SIGHUP, &sa, &old_sa), SyscallSucceeds());
  EXPECT_THAT(ioctl(replica_.get(), TIOCNOTTY), SyscallSucceeds());
  EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());
}

TEST_F(JobControlTest, ReleaseUnsetTTY) {
  ASSERT_THAT(ioctl(replica_.get(), TIOCNOTTY), SyscallFailsWithErrno(ENOTTY));
}

TEST_F(JobControlTest, ReleaseWrongTTY) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    TEST_PCHECK(ioctl(master_.get(), TIOCNOTTY) < 0 && errno == ENOTTY);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, ReleaseTTYNonLeader) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(!ioctl(replica_.get(), TIOCNOTTY));
      _exit(0);
    }

    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(wstatus == 0);
  });
  ASSERT_NO_ERRNO(ret);
}

TEST_F(JobControlTest, ReleaseTTYDifferentSession) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);

    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    pid_t grandchild = fork();
    if (!grandchild) {
      // Join a new session, then try to disconnect.
      TEST_PCHECK(setsid() >= 0);
      TEST_PCHECK(ioctl(replica_.get(), TIOCNOTTY));
      _exit(0);
    }

    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(wstatus == 0);
  });
  ASSERT_NO_ERRNO(ret);
}

// Used by the child process spawned in ReleaseTTYSignals to track received
// signals.
static int received;

void sig_handler(int signum) { received |= signum; }

// When the session leader releases its controlling terminal, the foreground
// process group gets SIGHUP, then SIGCONT. This test:
// - Spawns 2 threads
// - Has thread 1 return 0 if it gets both SIGHUP and SIGCONT
// - Has thread 2 leave the foreground process group, and return non-zero if it
//   receives any signals.
// - Has the parent thread release its controlling terminal
// - Checks that thread 1 got both signals
// - Checks that thread 2 didn't get any signals.
TEST_F(JobControlTest, ReleaseTTYSignals) {
  ASSERT_THAT(ioctl(replica_.get(), TIOCSCTTY, 0), SyscallSucceeds());

  received = 0;
  struct sigaction sa = {};
  sa.sa_handler = sig_handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGHUP);
  sigaddset(&sa.sa_mask, SIGCONT);
  sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL);

  pid_t same_pgrp_child = fork();
  if (!same_pgrp_child) {
    // The child will wait for SIGHUP and SIGCONT, then return 0. It begins with
    // SIGHUP and SIGCONT blocked. We install signal handlers for those signals,
    // then use sigsuspend to wait for those specific signals.
    TEST_PCHECK(!sigaction(SIGHUP, &sa, NULL));
    TEST_PCHECK(!sigaction(SIGCONT, &sa, NULL));
    sigset_t mask;
    sigfillset(&mask);
    sigdelset(&mask, SIGHUP);
    sigdelset(&mask, SIGCONT);
    while (received != (SIGHUP | SIGCONT)) {
      sigsuspend(&mask);
    }
    _exit(0);
  }

  // We don't want to block these anymore.
  sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

  // This child will return non-zero if either SIGHUP or SIGCONT are received.
  pid_t diff_pgrp_child = fork();
  if (!diff_pgrp_child) {
    TEST_PCHECK(!setpgid(0, 0));
    TEST_PCHECK(pause());
    _exit(1);
  }

  EXPECT_THAT(setpgid(diff_pgrp_child, diff_pgrp_child), SyscallSucceeds());

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sighup_sa = {};
  sighup_sa.sa_handler = SIG_IGN;
  sighup_sa.sa_flags = 0;
  sigemptyset(&sighup_sa.sa_mask);
  struct sigaction old_sa;
  EXPECT_THAT(sigaction(SIGHUP, &sighup_sa, &old_sa), SyscallSucceeds());

  // Release the controlling terminal, sending SIGHUP and SIGCONT to all other
  // processes in this process group.
  EXPECT_THAT(ioctl(replica_.get(), TIOCNOTTY), SyscallSucceeds());

  EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());

  // The child in the same process group will get signaled.
  int wstatus;
  EXPECT_THAT(waitpid(same_pgrp_child, &wstatus, 0),
              SyscallSucceedsWithValue(same_pgrp_child));
  EXPECT_EQ(wstatus, 0);

  // The other child will not get signaled.
  EXPECT_THAT(waitpid(diff_pgrp_child, &wstatus, WNOHANG),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(kill(diff_pgrp_child, SIGKILL), SyscallSucceeds());
}

// Used by the child process spawned in
// ControllingProcessPersistsAfterChildExists to track received signals.
static int received2;

void sig_handler2(int signum) { received2 |= signum; }

// NOTE(gvisor.dev/issue/9898): Regression test. Tests that a TTY's controlling
// process is not cleared when a non-controlling process exits.
TEST_F(JobControlTest, ControllingProcessPersistsAfterChildExists) {
  // Set the controlling process for the PTY.
  ASSERT_THAT(ioctl(replica_.get(), TIOCSCTTY, 0), SyscallSucceeds());

  // Fork a child, which does nothing and exits. We expect that this process
  // is still the controlling process, so is capable of receiving signals.
  ASSERT_NO_ERRNO(RunInChild([=]() {}));

  // Install handler for SIGINT.
  received2 = 0;
  struct sigaction sa = {};
  sa.sa_handler = sig_handler2;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  ASSERT_THAT(sigaction(SIGINT, &sa, NULL), SyscallSucceeds());

  // Send ^C.
  constexpr char kInput = ControlCharacter('C');
  ASSERT_THAT(WriteFd(master_.get(), &kInput, 1), SyscallSucceedsWithValue(1));

  // Ensure we got the signal. Wait at most for kTimeout.
  absl::Time end = absl::Now() + kTimeout;
  while (received2 != SIGINT) {
    absl::SleepFor(absl::Seconds(1));
    if (end < absl::Now()) {
      FAIL() << "Timed out waiting for SIGINT signal.";
      break;
    }
  }

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sighup_sa = {};
  sighup_sa.sa_handler = SIG_IGN;
  sighup_sa.sa_flags = 0;
  sigemptyset(&sighup_sa.sa_mask);
  struct sigaction old_sa;
  EXPECT_THAT(sigaction(SIGHUP, &sighup_sa, &old_sa), SyscallSucceeds());

  // Release the controlling terminal and restore the old SIGHUP handler.
  EXPECT_THAT(ioctl(replica_.get(), TIOCNOTTY), SyscallSucceeds());
  EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());
}

TEST_F(JobControlTest, GetForegroundProcessGroup) {
  auto res = RunInChild([=]() {
    pid_t pid, foreground_pgid;
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 1));
    TEST_PCHECK(!ioctl(replica_.get(), TIOCGPGRP, &foreground_pgid));
    TEST_PCHECK((pid = getpid()) >= 0);
    TEST_PCHECK(pid == foreground_pgid);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, GetForegroundProcessGroupNonControlling) {
  // At this point there's no controlling terminal, so TIOCGPGRP should fail.
  pid_t foreground_pgid;
  ASSERT_THAT(ioctl(replica_.get(), TIOCGPGRP, &foreground_pgid),
              SyscallFailsWithErrno(ENOTTY));
}

// This test:
// - sets itself as the foreground process group
// - creates a child process in a new process group
// - sets that child as the foreground process group
// - kills its child and sets itself as the foreground process group.
TEST_F(JobControlTest, SetForegroundProcessGroup) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    // Ignore SIGTTOU so that we don't stop ourself when calling tcsetpgrp.
    struct sigaction sa = {};
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTTOU, &sa, NULL);

    // Set ourself as the foreground process group.
    TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));

    // Create a new process that just waits to be signaled.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(!pause());
      // We should never reach this.
      _exit(1);
    }

    // Make the child its own process group, then make it the controlling
    // process group of the terminal.
    TEST_PCHECK(!setpgid(grandchild, grandchild));
    TEST_PCHECK(!tcsetpgrp(replica_.get(), grandchild));

    // Sanity check - we're still the controlling session.
    TEST_PCHECK(getsid(0) == getsid(grandchild));

    // Signal the child, wait for it to exit, then retake the terminal.
    TEST_PCHECK(!kill(grandchild, SIGTERM));
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(WIFSIGNALED(wstatus));
    TEST_PCHECK(WTERMSIG(wstatus) == SIGTERM);

    // Set ourself as the foreground process.
    pid_t pgid;
    TEST_PCHECK((pgid = getpgid(0)) >= 0);
    TEST_PCHECK(!tcsetpgrp(replica_.get(), pgid));
  });
  ASSERT_NO_ERRNO(res);
}

// This test verifies if a SIGTTOU signal is sent to the calling process's group
// when tcsetpgrp is called by a background process
TEST_F(JobControlTest, SetForegroundProcessGroupSIGTTOUBackground) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    pid_t grandchild = fork();
    if (!grandchild) {
      // Assign a different pgid to the child so it will result as
      // a background process.
      TEST_PCHECK(!setpgid(grandchild, getpid()));
      TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));
      // We should never reach this.
      _exit(1);
    }
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, WSTOPPED) == grandchild);
    TEST_PCHECK(WSTOPSIG(wstatus) == SIGTTOU);

    // The child's `tcsetpgrp` got signalled and so should not have
    // taken effect. Verify that.
    TEST_PCHECK(tcgetpgrp(replica_.get()) == getpid());
    EXPECT_THAT(kill(grandchild, SIGKILL), SyscallSucceeds());
  });
  ASSERT_NO_ERRNO(res);
}

// This test verifies that a SIGTTOU signal is not delivered to
// a background process which calls tcsetpgrp and is ignoring SIGTTOU
TEST_F(JobControlTest, SetForegroundProcessGroupSIGTTOUIgnored) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    pid_t grandchild = fork();
    if (!grandchild) {
      // Ignore SIGTTOU so the child in background won't
      // be stopped when it will call tcsetpgrp
      struct sigaction sa = {};
      sa.sa_handler = SIG_IGN;
      sa.sa_flags = 0;
      sigemptyset(&sa.sa_mask);
      sigaction(SIGTTOU, &sa, NULL);
      // Assign a different pgid to the child so it will result as
      // a background process.
      TEST_PCHECK(!setpgid(grandchild, getpid()));
      TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));
      _exit(0);
    }
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, WSTOPPED) == grandchild);
    TEST_PCHECK(WSTOPSIG(wstatus) != SIGTTOU);
    TEST_PCHECK(WIFEXITED(wstatus));
  });
  ASSERT_NO_ERRNO(res);
}

// This test verifies that a SIGTTOU signal is not delivered to
// a background process which calls tcsetpgrp and is blocking SIGTTOU
TEST_F(JobControlTest, SetForegroundProcessGroupSIGTTOUBlocked) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    pid_t grandchild = fork();
    if (!grandchild) {
      // Block SIGTTOU so the child in background won't
      // be stopped when it will call tcsetpgrp
      sigset_t signal_set;
      sigemptyset(&signal_set);
      sigaddset(&signal_set, SIGTTOU);
      // Block SIGTTIN as well, to make sure that the kernel isn't
      // checking for "blocked == [SIGTTOU]" (see issue 7941 for
      // context).
      sigaddset(&signal_set, SIGTTIN);
      sigprocmask(SIG_BLOCK, &signal_set, NULL);
      // Assign a different pgid to the child so it will result as
      // a background process.
      TEST_PCHECK(!setpgid(grandchild, getpid()));
      TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));
      // Unmask the signals to make sure we still don't get
      // signaled. That would happen if `tcsetpgrp` enqueued the
      // signal through the mask -- we would not yet have received it,
      // because of the mask.
      sigprocmask(SIG_UNBLOCK, &signal_set, NULL);
      _exit(0);
    }
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, WSTOPPED) == grandchild);
    TEST_PCHECK(WSTOPSIG(wstatus) != SIGTTOU);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetForegroundProcessGroupWrongTTY) {
  pid_t pid = getpid();
  ASSERT_THAT(ioctl(replica_.get(), TIOCSPGRP, &pid),
              SyscallFailsWithErrno(ENOTTY));
}

TEST_F(JobControlTest, SetForegroundProcessGroupNegPgid) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    pid_t pid = -1;
    TEST_PCHECK(ioctl(replica_.get(), TIOCSPGRP, &pid) && errno == EINVAL);
  });
  ASSERT_NO_ERRNO(ret);
}

TEST_F(JobControlTest, SetForegroundProcessGroupEmptyProcessGroup) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    // Create a new process, put it in a new process group, make that group the
    // foreground process group, then have the process wait.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(!setpgid(0, 0));
      _exit(0);
    }

    // Wait for the child to exit.
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    // The child's process group doesn't exist anymore - this should fail.
    TEST_PCHECK(ioctl(replica_.get(), TIOCSPGRP, &grandchild) != 0 &&
                errno == ESRCH);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetForegroundProcessGroupDifferentSession) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    int sync_setsid[2];
    int sync_exit[2];
    TEST_PCHECK(pipe(sync_setsid) >= 0);
    TEST_PCHECK(pipe(sync_exit) >= 0);

    // Create a new process and put it in a new session.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(setsid() >= 0);
      // Tell the parent we're in a new session.
      char c = 'c';
      TEST_PCHECK(WriteFd(sync_setsid[1], &c, 1) == 1);
      TEST_PCHECK(ReadFd(sync_exit[0], &c, 1) == 1);
      _exit(0);
    }

    // Wait for the child to tell us it's in a new session.
    char c = 'c';
    TEST_PCHECK(ReadFd(sync_setsid[0], &c, 1) == 1);

    // Child is in a new session, so we can't make it the foregroup process
    // group.
    TEST_PCHECK(ioctl(replica_.get(), TIOCSPGRP, &grandchild) &&
                errno == EPERM);

    TEST_PCHECK(WriteFd(sync_exit[1], &c, 1) == 1);

    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(WIFEXITED(wstatus));
    TEST_PCHECK(!WEXITSTATUS(wstatus));
  });
  ASSERT_NO_ERRNO(ret);
}

TEST_F(JobControlTest, SetGetSession) {
  auto res = RunInChild([=]() {
    pid_t sid = setsid();
    TEST_PCHECK(sid >= 0);
    TEST_PCHECK(getsid(0) == sid);
    TEST_PCHECK(getpid() == sid);
  });
  ASSERT_NO_ERRNO(res);
}

// Verify that we don't hang when creating a new session from an orphaned
// process group (b/139968068). Calling setsid() creates an orphaned process
// group, as process groups that contain the session's leading process are
// orphans.
//
// We create 2 sessions in this test. The init process in gVisor is considered
// not to be an orphan (see sessions.go), so we have to create a session from
// which to create a session. The latter session is being created from an
// orphaned process group.
TEST_F(JobControlTest, OrphanRegression) {
  pid_t session_2_leader = fork();
  if (!session_2_leader) {
    TEST_PCHECK(setsid() >= 0);

    pid_t session_3_leader = fork();
    if (!session_3_leader) {
      TEST_PCHECK(setsid() >= 0);

      _exit(0);
    }

    int wstatus;
    TEST_PCHECK(waitpid(session_3_leader, &wstatus, 0) == session_3_leader);
    TEST_PCHECK(wstatus == 0);

    _exit(0);
  }

  int wstatus;
  ASSERT_THAT(waitpid(session_2_leader, &wstatus, 0),
              SyscallSucceedsWithValue(session_2_leader));
  ASSERT_EQ(wstatus, 0);
}

// Test setting a controlling tty, then exiting, then re-using the same tty in a
// different process.
//
// Regression test for https://github.com/google/gvisor/issues/9642.
TEST_F(JobControlTest, ReuseControllingTTYAfterExit) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);
  });
  ASSERT_NO_ERRNO(res);

  auto res2 = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);
  });
  ASSERT_NO_ERRNO(res2);
}

// TCSBRK ioctl should succeed on both master and replica PTY ends.
// For PTYs, TCSBRK is a no-op (no real hardware break to send).
TEST_F(PtyTest, TCSBRKSucceeds) {
  // TCSBRK with arg=0 (send break) should be a no-op for PTYs.
  EXPECT_THAT(ioctl(master_.get(), TCSBRK, 0), SyscallSucceeds());
  EXPECT_THAT(ioctl(replica_.get(), TCSBRK, 0), SyscallSucceeds());

  // TCSBRK with arg=1 (tcdrain) should also succeed.
  EXPECT_THAT(ioctl(master_.get(), TCSBRK, 1), SyscallSucceeds());
  EXPECT_THAT(ioctl(replica_.get(), TCSBRK, 1), SyscallSucceeds());
}

// TCFLSH ioctl should flush the appropriate queues.
TEST_F(PtyTest, TCFLSHFlushesInput) {
  DisableCanonicalAndEcho();

  // Write data from master to replica input.
  constexpr char kInput[] = "hello";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(kInput) - 1));

  // Flush the replica input queue.
  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, TCIFLUSH), SyscallSucceeds());

  // Replica should have no data to read now.
  char buf[16];
  EXPECT_THAT(ReadFd(replica_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(EAGAIN));
}

// Test for caller-aware TCFLSH semantics on the master side.
TEST_F(PtyTest, TCFLSHFlushesMasterInput) {
  DisableCanonicalAndEcho();

  constexpr char kInput[] = "bye";
  ASSERT_THAT(WriteFd(replica_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));
  ASSERT_NO_ERRNO(WaitUntilReceived(master_.get(), sizeof(kInput) - 1));

  EXPECT_THAT(ioctl(master_.get(), TCFLSH, TCIFLUSH), SyscallSucceeds());

  char buf[16];
  EXPECT_THAT(ReadFd(master_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(EAGAIN));
}

// TCOFLUSH on the replica drops data queued for the master.
TEST_F(PtyTest, TCFLSHFlushesReplicaOutput) {
  DisableCanonicalAndEcho();

  constexpr char kOutput[] = "world";
  ASSERT_THAT(WriteFd(replica_.get(), kOutput, sizeof(kOutput) - 1),
              SyscallSucceedsWithValue(sizeof(kOutput) - 1));
  ASSERT_NO_ERRNO(WaitUntilReceived(master_.get(), sizeof(kOutput) - 1));

  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, TCOFLUSH), SyscallSucceeds());

  char buf[16];
  EXPECT_THAT(ReadFd(master_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(EAGAIN));
}

// TCIOFLUSH clears both directions from the caller's point of view.
TEST_F(PtyTest, TCFLSHFlushesBothDirections) {
  DisableCanonicalAndEcho();

  constexpr char kInput[] = "input";
  constexpr char kOutput[] = "output";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));
  ASSERT_THAT(WriteFd(replica_.get(), kOutput, sizeof(kOutput) - 1),
              SyscallSucceedsWithValue(sizeof(kOutput) - 1));
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(kInput) - 1));
  ASSERT_NO_ERRNO(WaitUntilReceived(master_.get(), sizeof(kOutput) - 1));

  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, TCIOFLUSH), SyscallSucceeds());

  char buf[16];
  EXPECT_THAT(ReadFd(replica_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(EAGAIN));
  EXPECT_THAT(ReadFd(master_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(EAGAIN));
}

// Replica-side flushes should surface TIOCPKT flush status to the master.
TEST_F(PtyTest, TCFLSHReplicaReportsPacketModeStatus) {
  EnablePacketMode();

  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, TCIFLUSH), SyscallSucceeds());
  ExpectMasterPacketStatus(TIOCPKT_FLUSHREAD);

  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, TCOFLUSH), SyscallSucceeds());
  ExpectMasterPacketStatus(TIOCPKT_FLUSHWRITE);

  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, TCIOFLUSH), SyscallSucceeds());
  ExpectMasterPacketStatus(TIOCPKT_FLUSHREAD | TIOCPKT_FLUSHWRITE);
}

// Master-side flushes should not generate packet mode status bytes.
TEST_F(PtyTest, TCFLSHMasterDoesNotReportPacketModeStatus) {
  EnablePacketMode();

  EXPECT_THAT(ioctl(master_.get(), TCFLSH, TCIFLUSH), SyscallSucceeds());
  ExpectMasterHasNoPacketStatus();

  EXPECT_THAT(ioctl(master_.get(), TCFLSH, TCOFLUSH), SyscallSucceeds());
  ExpectMasterHasNoPacketStatus();

  EXPECT_THAT(ioctl(master_.get(), TCFLSH, TCIOFLUSH), SyscallSucceeds());
  ExpectMasterHasNoPacketStatus();
}

// Flushing the master's input queue should wake a blocked replica writer.
TEST_F(PtyTest, TCFLSHWakesReplicaPolloutAfterMasterInputFlush) {
  DisableCanonicalAndEcho();
  FillUntilBlocked(replica_);

  struct pollfd initial = {replica_.get(), POLLOUT, 0};
  EXPECT_THAT(poll(&initial, 1, 0), SyscallSucceedsWithValue(0));

  absl::Notification notify;
  int sfd = replica_.get();
  ScopedThread th([sfd, &notify]() {
    notify.Notify();

    struct pollfd poll_fd = {sfd, POLLOUT, 0};
    EXPECT_THAT(
        RetryEINTR(poll)(&poll_fd, 1, absl::ToInt64Milliseconds(kTimeout)),
        SyscallSucceedsWithValue(1));
    EXPECT_EQ(poll_fd.revents & POLLOUT, POLLOUT);

    constexpr char kByte = 'r';
    EXPECT_THAT(RetryEINTR(write)(sfd, &kByte, 1), SyscallSucceedsWithValue(1));
  });

  notify.WaitForNotification();
  absl::SleepFor(absl::Seconds(1));
  EXPECT_THAT(ioctl(master_.get(), TCFLSH, TCIFLUSH), SyscallSucceeds());
}

// Flushing the replica's input queue should wake a blocked master writer.
// We use a blocking write() instead of poll(POLLOUT) because the master's
// POLLOUT is unreliable on native Linux (flip-buffer is consumed async).
TEST_F(PtyTest, TCFLSHWakesMasterWriteAfterReplicaInputFlush) {
  DisableCanonicalAndEcho();
  FillUntilWriteReturnsEAGAIN(master_);

  absl::Notification notify;
  int mfd = master_.get();
  ScopedThread th([mfd, &notify]() {
    // Clear O_NONBLOCK so write() blocks when the queue is full, rather than
    // returning EAGAIN. This gives us a reliable "blocked writer" to wake.
    int flags = fcntl(mfd, F_GETFL);
    ASSERT_GE(flags, 0);
    ASSERT_EQ(fcntl(mfd, F_SETFL, flags & ~O_NONBLOCK), 0);

    notify.Notify();

    constexpr char kByte = 'w';
    EXPECT_THAT(RetryEINTR(write)(mfd, &kByte, 1), SyscallSucceedsWithValue(1));
  });

  notify.WaitForNotification();
  absl::SleepFor(absl::Seconds(1));
  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, TCIFLUSH), SyscallSucceeds());
}

// TCFLSH with invalid argument should return EINVAL.
TEST_F(PtyTest, TCFLSHInvalidArg) {
  EXPECT_THAT(ioctl(replica_.get(), TCFLSH, 42), SyscallFailsWithErrno(EINVAL));
}

// When ISIG is disabled, signal characters (Ctrl-C, Ctrl-Z, Ctrl-\) should
// be passed through to the reader as ordinary characters, not generate signals.
// This matches Linux n_tty.c behavior: signal chars are only special when
// L_ISIG(tty) is true.
TEST_F(PtyTest, SignalCharPassedThroughWhenISIGDisabled) {
  // Disable ISIG.
  struct kernel_termios t = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
  t.c_lflag &= ~ISIG;
  // Also disable ICANON so we can read character by character.
  t.c_lflag &= ~ICANON;
  t.c_cc[VMIN] = 1;
  t.c_cc[VTIME] = 0;
  EXPECT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  // Write Ctrl-C to master.
  constexpr char kCtrlC = ControlCharacter('C');
  ASSERT_THAT(WriteFd(master_.get(), &kCtrlC, 1), SyscallSucceedsWithValue(1));

  // The signal character should appear on the replica as a normal byte.
  char buf = 0;
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), 1));
  ASSERT_THAT(ReadFd(replica_.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kCtrlC);
}

// When ISIG is enabled (default), signal characters should be consumed and
// NOT passed to the reading process. In Linux, n_tty_receive_signal_char()
// calls n_tty_flush_buffer_and_wake() which prevents the character from
// appearing in the read buffer.
TEST_F(PtyTest, SignalCharConsumedWhenISIGEnabled) {
  // Ensure ISIG is enabled (it should be by default).
  struct kernel_termios t = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
  t.c_lflag |= ISIG;
  // Disable ICANON for raw reading.
  t.c_lflag &= ~ICANON;
  t.c_cc[VMIN] = 1;
  t.c_cc[VTIME] = 0;
  EXPECT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  // Write Ctrl-C followed by a normal character.
  constexpr char kInput[] = {ControlCharacter('C'), 'a'};
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));

  // Only the normal character 'a' should be readable; Ctrl-C should have been
  // consumed by the signal delivery path.
  char buf = 0;
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), 1));
  ASSERT_THAT(ReadFd(replica_.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, 'a');
}

// When the PTY master is closed, SIGHUP should be sent to the foreground
// process group of the session that has this PTY as its controlling terminal.
// This matches Linux pty_close() -> tty_vhangup() behavior.
TEST_F(JobControlTest, SIGHUPOnMasterClose) {
  // Use a pipe to synchronize: the child signals readiness after setting up
  // its session and controlling terminal.
  int sync_pipe[2];
  ASSERT_THAT(pipe(sync_pipe), SyscallSucceeds());

  pid_t child = fork();
  if (child == 0) {
    close(sync_pipe[0]);  // Close read end in child.

    // Close the inherited master fd so that the parent holds the only
    // reference. pty_close/tty_vhangup fires only when the last master
    // fd is closed.
    close(master_.release());

    // Create new session and set the replica as controlling terminal.
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);

    // Install a SIGHUP handler that exits with a known status.
    struct sigaction sa = {};
    sa.sa_handler = [](int) { _exit(42); };
    sigemptyset(&sa.sa_mask);
    TEST_PCHECK(sigaction(SIGHUP, &sa, nullptr) >= 0);

    // Notify the parent that setup is complete.
    char c = 'r';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);
    close(sync_pipe[1]);

    // Sleep waiting for the signal. Use a timeout to avoid hanging the test.
    sleep(10);  // NOLINT(runtime/sleep): sleep() alone is async-signal-safe.
    // If we get here, SIGHUP was not received.
    _exit(1);
  }
  ASSERT_GT(child, 0);
  close(sync_pipe[1]);  // Close write end in parent.

  // Wait for the child to finish setting up its session and controlling
  // terminal.
  char c;
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  close(sync_pipe[0]);

  // Close the master end. This should trigger SIGHUP to the child.
  master_.reset();

  // Wait for the child and verify it received SIGHUP (exited with 42).
  int wstatus;
  ASSERT_THAT(waitpid(child, &wstatus, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(wstatus));
  EXPECT_EQ(WEXITSTATUS(wstatus), 42);
}

TEST_F(JobControlTest, SigwinchOnWindowSizeChange) {
  int sync_pipe[2];
  ASSERT_THAT(pipe(sync_pipe), SyscallSucceeds());

  pid_t child = fork();
  if (child == 0) {
    close(sync_pipe[0]);

    // Close inherited master.
    master_.reset();

    // Create new session and set replica as controlling terminal.
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);

    // Block SIGWINCH.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGWINCH);
    sigset_t old_set;
    TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, &old_set) == 0);

    // Notify parent we are ready.
    char c = 'r';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Wait for SIGWINCH (triggered by parent changing size on master).
    struct timespec timeout = {};
    timeout.tv_sec = 10;
    int sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig != SIGWINCH) {
      _exit(1);  // Failed to receive SIGWINCH.
    }

    // Notify parent we got it.
    c = '1';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Now wait for another SIGWINCH (triggered by parent changing size again).
    sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig != SIGWINCH) {
      _exit(2);  // Failed to receive second SIGWINCH.
    }

    // Notify parent we got it.
    c = '2';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Now expect NO SIGWINCH if we set the same size.
    timeout.tv_sec = 2;
    sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig == SIGWINCH) {
      _exit(3);  // Unexpected SIGWINCH.
    }

    // Notify parent.
    c = '3';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Test TIOCSWINSZ from replica (self-signaling).
    struct winsize ws = {};
    TEST_PCHECK(ioctl(replica_.get(), TIOCGWINSZ, &ws) == 0);
    ws.ws_row++;
    ws.ws_col++;
    TEST_PCHECK(ioctl(replica_.get(), TIOCSWINSZ, &ws) == 0);
    timeout.tv_sec = 10;
    sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    if (sig != SIGWINCH) {
      _exit(4);  // Failed to receive SIGWINCH after replica TIOCSWINSZ.
    }

    // Notify parent.
    c = '4';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    close(sync_pipe[1]);
    _exit(42);  // Success.
  }
  ASSERT_GT(child, 0);
  close(sync_pipe[1]);

  // Wait for child to be ready.
  char c;
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'r');

  // 1. Change size on master.
  struct winsize ws = {};
  ASSERT_THAT(ioctl(master_.get(), TIOCGWINSZ, &ws), SyscallSucceeds());
  ws.ws_row++;
  ws.ws_col++;
  ASSERT_THAT(ioctl(master_.get(), TIOCSWINSZ, &ws), SyscallSucceeds());

  // Wait for child to receive it.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '1');

  // 2. Change size on master again.
  ws.ws_row++;
  ws.ws_col++;
  ASSERT_THAT(ioctl(master_.get(), TIOCSWINSZ, &ws), SyscallSucceeds());

  // Wait for child to receive it.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '2');

  // 3. Set same size on master.
  ASSERT_THAT(ioctl(master_.get(), TIOCSWINSZ, &ws), SyscallSucceeds());

  // Wait for child to finish waiting.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '3');

  // Wait for child to perform self-signaling test.
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, '4');

  close(sync_pipe[0]);

  // Wait for child.
  int wstatus;
  ASSERT_THAT(waitpid(child, &wstatus, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(wstatus));
  EXPECT_EQ(WEXITSTATUS(wstatus), 42);
}

// A signal character signals the foreground process group of the session
// whose controlling terminal it is typed into, and is echoed.
TEST_F(JobControlTest, SignalCharSignalsForegroundAndEchoes) {
  int sync_pipe[2];
  ASSERT_THAT(pipe(sync_pipe), SyscallSucceeds());

  pid_t child = fork();
  if (child == 0) {
    close(sync_pipe[0]);
    master_.reset();

    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);

    sigset_t set;
    sigemptyset(&set);
    for (const SignalChar& sc : kSignalChars) {
      sigaddset(&set, sc.signal);
    }
    TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

    char c = 'r';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    // Report each signal the terminal sends.
    for (size_t i = 0; i < sizeof(kSignalChars) / sizeof(kSignalChars[0]);
         i++) {
      struct timespec timeout = {};
      timeout.tv_sec = 10;
      int sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
      TEST_PCHECK(sig > 0);
      c = sig;
      TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);
    }
    _exit(0);
  }
  ASSERT_GT(child, 0);
  close(sync_pipe[1]);

  char c;
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'r');

  for (const SignalChar& sc : kSignalChars) {
    ASSERT_THAT(WriteFd(master_.get(), &sc.input, 1),
                SyscallSucceedsWithValue(1));
    ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
    EXPECT_EQ(c, sc.signal);
    ExpectEcho(master_, sc.echo);
  }
  close(sync_pipe[0]);

  int wstatus;
  ASSERT_THAT(waitpid(child, &wstatus, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(wstatus)) << wstatus;
  EXPECT_EQ(WEXITSTATUS(wstatus), 0);
}

// Typing a line ahead and then Ctrl-C while the foreground process is not
// reading its terminal echoes the typeahead and interrupts it immediately.
TEST_F(JobControlTest, TypeaheadSignalInterruptsForeground) {
  int sync_pipe[2];
  ASSERT_THAT(pipe(sync_pipe), SyscallSucceeds());

  pid_t child = fork();
  if (child == 0) {
    close(sync_pipe[0]);
    master_.reset();

    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0) >= 0);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

    char c = 'r';
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);

    struct timespec timeout = {};
    timeout.tv_sec = 10;
    int sig = RetryEINTR(sigtimedwait)(&set, nullptr, &timeout);
    TEST_PCHECK(sig == SIGINT);
    c = sig;
    TEST_PCHECK(WriteFd(sync_pipe[1], &c, 1) == 1);
    _exit(0);
  }
  ASSERT_GT(child, 0);
  close(sync_pipe[1]);

  char c;
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, 'r');

  WriteAll(master_, "ls\n");
  ExpectEcho(master_, "ls\r\n");
  WriteAll(master_, "ab");
  ExpectEcho(master_, "ab");
  WriteAll(master_, std::string(1, ControlCharacter('C')));
  ASSERT_THAT(ReadFd(sync_pipe[0], &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, SIGINT);
  ExpectEcho(master_, "^C");
  ExpectFinished(replica_);
  close(sync_pipe[0]);

  int wstatus;
  ASSERT_THAT(waitpid(child, &wstatus, 0), SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFEXITED(wstatus)) << wstatus;
  EXPECT_EQ(WEXITSTATUS(wstatus), 0);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
