FROM ubuntu:22.04
# Install Boost 1.87.0
RUN wget https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz
RUN tar -xzf boost_1_87_0.tar.gz
RUN pushd boost_1_87_0
RUN ./bootstrap.sh
RUN sudo ./b2 install
RUN popd
# Install MySQL
RUN wget https://dev.mysql.com/get/mysql-apt-config_0.8.33-1_all.deb
RUN sudo dpkg -i mysql-apt-config_0.8.33-1_all.deb
RUN sudo apt-get update
RUN sudo apt-get install mysql-server 
# Install Redis-Stack
RUN sudo apt-get install lsb-release curl gpg
RUN curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
RUN sudo chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
RUN sudo apt-get update
RUN sudo apt-get install redis-stack-server
RUN sudo systemctl enable redis-stack-server
RUN sudo systemctl start redis-stack-server
