FROM ubuntu

RUN apt-get update
RUN apt-get install software-properties-common -y
RUN apt-get update
RUN apt-add-repository ppa:ansible/ansible -y
RUN apt update
RUN apt install ansible -y

CMD ["echo","Container created"]

#For configuring the hosts file
RUN echo [hpe] >>[] /etc/ansible/hosts
RUN echo hpe1    baseuri=10.16.40.12 >> /etc/ansible/hosts
RUN echo [myhosts:children] >> /etc/ansible/hosts
RUN echo hpe >> /etc/ansible/hosts
RUN echo [myhosts:vars] >> /etc/ansible/hosts
RUN echo username=admin >> /etc/ansible/hosts
RUN echo password=admin123 >> /etc/ansible/hosts

#Building and Installing hpe.redfish collection
RUN ansible-galaxy collection build --force .
RUN ansible-galaxy collection install *.tar.gz
WORKDIR /root/.ansible/collections/ansible_collections/hpe/redfish
