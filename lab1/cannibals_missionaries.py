import os
import sys
import random
import time
import sysv_ipc

MISSIONARY_ROLE = 'missionary'
CANNIBAL_ROLE = 'cannibal'

MISSIONARY_MQ_TYPE = 1
CANNIBAL_MQ_TYPE = 2

BOAT_ENTER_MSG = 'CROSS THE RIVER'

def run_child(mq, role, mq_snd_type, mq_rcv_type):
    id = str(os.getpid())
    name = role + ':' + id
    print(name, 'trying to cross the river..', ' sending: ', id, 'with type:', mq_snd_type)
    mq.send(message=id, type=mq_snd_type)
    msg, _ = mq.receive(type = mq_rcv_type)
    msg = msg.decode('utf-8')
    print(name, 'received: ', msg)
    exit(0)

def nonblock_mq_receive(mq, mq_type):
    try:
        msg, _ = mq.receive(block=False, type=mq_type)
        return msg
    except sysv_ipc.BusyError:
        return None

def main():
    N, M = int(sys.stdin.readline()), int(sys.stdin.readline())
    if N < 1 or M < 1:
        print('N and M must be > 0')
        exit(1)
    roles = [CANNIBAL_ROLE] * N + [MISSIONARY_ROLE] * M
    random.shuffle(roles)

    mq = sysv_ipc.MessageQueue(None, sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL)
    cur_child_mq_type = 3
    child_pids_mq_type = {}
    for role in roles:
        child_pid = os.fork()
        role_mq_type = MISSIONARY_MQ_TYPE if role == MISSIONARY_ROLE else CANNIBAL_MQ_TYPE
        if child_pid == 0:
            run_child(mq, role, role_mq_type, cur_child_mq_type)
        else:
            child_pids_mq_type[child_pid] = cur_child_mq_type
            cur_child_mq_type += 1

    ## CAVEATS:
    #   - travellers: max 3, min 1
    #   - num of cannibals < num of missionaries
    ## LOGIC:
    #   - take 1 missionary and then try to take 1 cannibal
    #   - try to take another missionary (or 2 of them if there are no cannibals)
    #   - if boat is empty then exit(0)
    while True:
        time.sleep(4)  # wait while passengers request onboarding
        elected_pids = []
        elected_pid = nonblock_mq_receive(mq, MISSIONARY_MQ_TYPE)
        if not elected_pid:
            break
        info_msg = '\n'

        info_msg += 'boat onboarding:\n'
        info_msg += '\t- ' + MISSIONARY_ROLE + ':' + elected_pid.decode('utf-8')
        elected_pids.append(int(elected_pid.decode('utf-8')))
        elected_pid = nonblock_mq_receive(mq, CANNIBAL_MQ_TYPE)
        if elected_pid:
            elected_pids.append(int(elected_pid.decode('utf-8')))
            info_msg += '\n\t- ' + CANNIBAL_ROLE + ':' + elected_pid.decode('utf-8') + '\n'
        print(info_msg)
        for pid in elected_pids:
            mq.send(BOAT_ENTER_MSG, type = child_pids_mq_type[pid])

    print('Exiting successfully!')

if __name__ == "__main__":
    main()