/* Copyright (c) 2010-2016 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef CORE_ARBITER_SYSCALL_H
#define CORE_ARBITER_SYSCALL_H

#include <dirent.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <cstdio>
#include "CoreArbiterCommon.h"

namespace CoreArbiter {

/**
 * This class provides a mechanism for invoking system calls and other
 * library functions that makes it easy to intercept the calls with a
 * mock class (e.g. MockSyscall) for testing. When system calls are
 * invoked through this base class they have the same behavior as if
 * they were invoked directly.
 *
 * The methods have the same names, arguments, and behavior as the
 * corresponding Linux/POSIX functions; see the man pages for details.
 */
class Syscall {
  public:
    Syscall() {}
    virtual ~Syscall() {}

    virtual int accept(int sockfd, sockaddr* addr, socklen_t* addrlen) {
        return ::accept(sockfd, addr, addrlen);
    }
    virtual int bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
        return ::bind(sockfd, addr, addrlen);
    }
    virtual int chmod(const char* path, mode_t mode) {
        return ::chmod(path, mode);
    }
    virtual int close(int fd) { return ::close(fd); }
    virtual int closedir(DIR* dirp) { return ::closedir(dirp); }
    virtual int connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
        return ::connect(sockfd, addr, addrlen);
    }
    virtual int epoll_create(int size) { return ::epoll_create(size); }
    virtual int epoll_ctl(int epfd, int op, int fd, epoll_event* event) {
        return ::epoll_ctl(epfd, op, fd, event);
    }
    virtual int epoll_wait(int epfd, epoll_event* events, int maxEvents,
                           int timeout) {
        return ::epoll_wait(epfd, events, maxEvents, timeout);
    }
    virtual void exit(int status) { ::exit(status); }
    virtual int ioctl(int fd, int reqType, void* request) {
        return ::ioctl(fd, reqType, request);
    }
    virtual int fcntl(int fd, int cmd, int arg1) {
        return ::fcntl(fd, cmd, arg1);
    }
    virtual FILE* fopen(const char* filename, const char* mode) {
        return ::fopen(filename, mode);
    }
    virtual size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
        return ::fread(ptr, size, nmemb, stream);
    }
    virtual int ftruncate(int fd, off_t length) {
        return ::ftruncate(fd, length);
    }
    virtual int futexWait(int* addr, int value) {
        return static_cast<int>(
            ::syscall(SYS_futex, addr, FUTEX_WAIT, value, NULL, NULL, 0));
    }
    virtual int futexWake(int* addr, int count) {
        return static_cast<int>(
            ::syscall(SYS_futex, addr, FUTEX_WAKE, count, NULL, NULL, 0));
    }
    virtual size_t fwrite(const void* src, size_t size, size_t count, FILE* f) {
        return ::fwrite(src, size, count, f);
    }
    virtual uid_t geteuid() { return ::geteuid(); }
    virtual int getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen) {
        return ::getsockname(sockfd, addr, addrlen);
    }
    virtual pid_t gettid() { return (pid_t)syscall(SYS_gettid); }
    virtual pid_t getpid() { return ::getpid(); }
    virtual int listen(int sockfd, int backlog) {
        return ::listen(sockfd, backlog);
    }
    virtual int mkdir(const char* pathname, mode_t mode) {
        return ::mkdir(pathname, mode);
    }
    virtual void* mmap(void* addr, size_t length, int prot, int flags, int fd,
                       off_t offset) {
        return ::mmap(addr, length, prot, flags, fd, offset);
    }
    virtual int open(const char* path, int oflag) {
        return ::open(path, oflag);
    }
    virtual int open(const char* path, int oflag, mode_t mode) {
        return ::open(path, oflag, mode);
    }
    virtual DIR* opendir(const char* name) { return ::opendir(name); }
    virtual int pipe(int fds[2]) { return ::pipe(fds); }
    virtual ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
        return ::pread(fd, buf, count, offset);
    }
    virtual ssize_t pwrite(int fd, const void* buf, size_t count,
                           off_t offset) {
        return ::pwrite(fd, buf, count, offset);
    }
    virtual struct dirent* readdir(DIR* dirp) { return ::readdir(dirp); }
    virtual ssize_t recv(int sockfd, void* buf, size_t len, int flags) {
        return ::recv(sockfd, buf, len, flags);
    }
    virtual ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags,
                             sockaddr* from, socklen_t* fromLen) {
        return ::recvfrom(sockfd, buf, len, flags, from, fromLen);
    }
    virtual ssize_t recvmmsg(int sockfd, struct mmsghdr* msgvec,
                             unsigned int vlen, unsigned int flags,
                             struct timespec* timeout) {
        return ::recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    }
    virtual int rmdir(const char* pathname) { return ::rmdir(pathname); }
    virtual int select(int nfds, fd_set* readfds, fd_set* writefds,
                       fd_set* errorfds, struct timeval* timeout) {
        return ::select(nfds, readfds, writefds, errorfds, timeout);
    }
    virtual ssize_t send(int sockfd, const void* buf, size_t len, int flags) {
        return ::send(sockfd, buf, len, flags);
    }
    virtual ssize_t sendmsg(int sockfd, const msghdr* msg, int flags) {
        return ::sendmsg(sockfd, msg, flags);
    }
    virtual ssize_t sendto(int socket, const void* buffer, size_t length,
                           int flags, const struct sockaddr* destAddr,
                           socklen_t destLen) {
        return ::sendto(socket, buffer, length, flags, destAddr, destLen);
    }
    virtual int setsockopt(int sockfd, int level, int optname,
                           const void* optval, socklen_t optlen) {
        return ::setsockopt(sockfd, level, optname, optval, optlen);
    }
    virtual int socket(int domain, int type, int protocol) {
        return ::socket(domain, type, protocol);
    }
    virtual int stat(const char* path, struct stat* buf) {
        return ::stat(path, buf);
    }
    virtual int timerfd_create(int clockid, int flags) {
        return ::timerfd_create(clockid, flags);
    }
    virtual int timerfd_settime(int fd, int flags,
                                const struct itimerspec* newVal,
                                struct itimerspec* oldVal) {
        return ::timerfd_settime(fd, flags, newVal, oldVal);
    }
    virtual int unlink(const char* pathname) { return ::unlink(pathname); }
    virtual ssize_t write(int fd, const void* buf, size_t count) {
        return ::write(fd, buf, count);
    }
    virtual ssize_t read(int fd, void* buf, size_t count) {
        return ::read(fd, buf, count);
    }

    virtual int flock(int fd, int operation) { return ::flock(fd, operation); }
};

/**
 * Used to set/restore static Syscall* class members for testing.
 */
struct SyscallGuard {
    SyscallGuard(Syscall** sys, Syscall* newSys) : sys(sys), old(*sys) {
        *sys = newSys;
    }
    ~SyscallGuard() { *sys = old; }
    Syscall** sys;
    Syscall* old;
};

}  // namespace CoreArbiter

#endif  // CORE_ARBITER_SYSCALL_H
