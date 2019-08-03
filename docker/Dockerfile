# run systemctl restart docker before build this.
#docker build --no-cache -t ubuntu16 .
#docker run -p 2323:2323 -i -t --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --name fengshui ubuntu16 /bin/bash 
#for glibc version 2.23

# host -> container
#docker cp /home/synod2/synod2/hackctf/fengshui/fengshui fengshui:/root/fengshui

#container -> host
#docker cp fengshui:/path/foo.txt /path/foo.txt

#docker attach fengshui
#docker exec fengshui /bin/sh

# gdb q 
# target remote 127.0.0.1:2323 fengshui

# gdbserver 127.0.0.1:2323 fengshui


FROM ubuntu:16.04
MAINTAINER synod2
 
ENV DEBIAN_FRONTEND=noninteractive
 
WORKDIR /root
 
RUN dpkg --add-architecture i386
 
RUN apt-get -y update && apt-get install -y locales vim gdb python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential lrzsz ssh libc6-dbg libc6-dbg:i386 libc6:i386 libncurses5:i386 libstdc++6:i386 zlib1g:i386 ltrace strace ruby-dev net-tools tmux
 
RUN pip install --upgrade pip && pip2 install --no-cache-dir --upgrade pwntools
 
RUN gem install one_gadget seccomp-tools heapinfo
 
RUN rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
 
RUN git clone https://github.com/longld/peda.git ~/peda && \
    echo "source ~/peda/peda.py" >> ~/.gdbinit
 
RUN git clone https://github.com/scwuaptx/Pwngdb.git && \
    cp ~/Pwngdb/.gdbinit ~/
 
RUN git clone git://github.com/Mipu94/peda-heap.git ~/peda-heap && \
    echo "source ~/peda-heap/peda.py" >> ~/.gdbinit
 
ENV LANG en_US.utf8
 
EXPOSE 22
 
CMD rm -rf .cache