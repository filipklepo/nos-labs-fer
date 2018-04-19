import os
import sys
import time
from enum import Enum
import threading
import select

## TODOS
# - [x] Establish communication between each pair of philosophers
# - [x] Implement R-A algo

class RAMessageType(Enum):
    R = 1
    A = 2

class RAMessage:

    MESSAGE_REQUEST_PREFIX = 'R'
    MESSAGE_ANSWER_PREFIX = 'A'

    def __init__(self, type = None, id = None, clock = None, repr = None):
        if repr:
            prefix = repr[0:1]
            chunks = repr[2:-1].split(',')
            if prefix != RAMessage.MESSAGE_REQUEST_PREFIX and prefix != RAMessage.MESSAGE_ANSWER_PREFIX:
                raise ValueError('Illegal message prefix: ', prefix)
            self.type = RAMessageType.R if prefix == RAMessage.MESSAGE_REQUEST_PREFIX else RAMessageType.A
            self.id = int(chunks[0])
            self.clock = int(chunks[1])
        else:
            self.type = type
            self.id = id
            self.clock = clock

    def __str__(self):
        return self.type.name + '(' + str(self.id) + ',' + str(self.clock)+ ')'

class RANodeContext:

    def __init__(self, clock=0, request = None):
        self.lock = threading.Lock()
        self.clock = clock
        self.request = request

    def update_clock(self, message):
        self.clock = max(self.clock, message.clock) + 1

def answer(msg, name, id, w_fds):
    msg_arr_id = msg.id-1 if msg.id > id else msg.id
    msg_ans = RAMessage(type=RAMessageType.A, id=id, clock=msg.clock)
    os.write(w_fds[msg_arr_id], str(msg_ans).encode('utf-8'))
    print(name, 'send:', str(msg_ans))

def read_msg(fd):
    res = ''
    while True:
        c = os.read(fd, 1)
        c = c.decode('utf-8')
        res += c
        if c == ')':
            break
    return res

def r_thread(id, name, r_fds, w_fds, rnc):
    rnc.lock.acquire()
    answers = []
    requests = []
    while True:
        readable_fds = select.select(r_fds, [], [], 0.0)
        readable_fds = readable_fds[0]
        for readable_fd in readable_fds:
            text = read_msg(readable_fd)
            msg = RAMessage(repr=text)
            print(name, 'read:', msg)
            rnc.update_clock(msg)
            if msg.type == RAMessageType.A:
                answers.append(msg)
            else:
                if rnc.request and rnc.request.clock < msg.clock:
                    requests.append(msg)
                else:
                    answer(msg, name, id, w_fds)
        if rnc.request and len(answers) == len(r_fds):
            rnc.lock.release()
            answers = []
            rnc.request = None
            [answer(req_msg, name, id, w_fds) for req_msg in requests]
            requests = []
            time.sleep(5)
            rnc.lock.acquire()

def ko_thread(name, rnc):
    time.sleep(1) # attend conference
    rnc.lock.acquire()
    print(name, 'is at the table')
    time.sleep(3)
    rnc.lock.release()
    time.sleep(1) # attend conference

def philosopher(id, r_fds, w_fds):
    name = 'Philosopher_' + str(id)
    rnc = RANodeContext(clock=10 * id + id) # update clock when receiving message

    msg = RAMessage(type=RAMessageType.R, id=id, clock=rnc.clock)
    for w_fd in w_fds: #send request
        print(name, 'send:', str(msg))
        os.write(w_fd, str(msg).encode('utf-8'))
    rnc.request = msg

    r_t = threading.Thread(target=r_thread, args=(id, name, r_fds, w_fds, rnc))
    ko_t = threading.Thread(target=ko_thread, args=(name, rnc))
    r_t.start()
    time.sleep(1)
    ko_t.start()
    r_t.join()

def main():
    N = int(sys.stdin.readline())
    if N < 3:
        print('N must be > 2')
        exit(1)

    # create 2 pipes for each pair of processes (total of 2 * N-over-2 pipes)
    pipes = {}
    for i in range(N):
        pipes[str(i)] = [[],[]]
    for i in range(N):
        for j in range(i+1, N):
            fds_ij = os.pipe() # i (w) -> j (r)
            fds_ji = os.pipe() # j (w) -> i (r)
            pipes[str(i)][0].append(fds_ji)
            pipes[str(i)][1].append(fds_ij)
            pipes[str(j)][0].append(fds_ij)
            pipes[str(j)][1].append(fds_ji)

    pipes_fds = set()
    [pipes_fds.update(tuple) for value in pipes.values() for subvalue in value for tuple in subvalue]

    for i in range(N):
        child_pid = os.fork()
        if child_pid == 0:
            # close ALL unnecessary fds, map pipes[str(i)] to two lists of ints (fds)
            r_fds, w_fds = [], []
            for pipes_i in pipes:
                pipes_i_v = pipes[pipes_i]
                if i == int(pipes_i):
                    for ri, wi in pipes_i_v[0]:
                        r_fds.append(ri)
                    for ri, wi in pipes_i_v[1]:
                        w_fds.append(wi)

            [os.close(fd) for fd in pipes_fds if fd not in r_fds and fd not in w_fds]
            philosopher(i, r_fds, w_fds)
            exit(0)

    for i in range(N):
        os.wait()

if __name__ == '__main__':
    main()