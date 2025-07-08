# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # vagrant plugin install vagrant-vbguest
  #config.vbguest.auto_update = true
  #config.vbguest.auto_reboot = true

  config.vm.define "server" do |server|
    server.vm.box = "ubuntu/jammy64"
    server.vm.hostname = "server.pop"
    server.vm.network "private_network", ip: "192.168.56.10", hostname: true
    server.vm.synced_folder "./", "/vagrant"

    server.vm.provision "shell", inline: <<-SHELL
      echo "192.168.56.20 client" >> /etc/hosts
      apt-get --yes update
      apt-get --yes dist-upgrade
      apt-get --yes install vim iperf3 valgrind docker.io linux-tools-common linux-tools-generic pylint lldpd
      if [[ $(lsb_release -cs) =~ jammy ]] ; then
          apt-get --yes install linux-generic-hwe-22.04-edge
      fi
      apt-get --yes autoremove
      adduser vagrant docker
      # For xdp_sampler testing
      mkdir -p /oc/local/config/
      echo moo > /oc/local/config/srvtype
      echo 'export INTERFACE=enp0s8' > /etc/profile.d/xdp_test_env.sh
      echo 'export BUILD_PATH=/vagrant/build' >> /etc/profile.d/xdp_test_env.sh
      /vagrant/build.sh -i
    SHELL

    # vagrant plugin install vagrant-reload
    server.vm.provision :reload
  end

# XXX: No noble image yet for Vagrant...
#  config.vm.define "server-noble" do |server|
#    server.vm.box = "ubuntu/noble64"
#    server.vm.hostname = "server.pop"
#    server.vm.network "private_network", ip: "192.168.56.11", hostname: true
#    server.vm.synced_folder "./", "/vagrant"
#
#    server.vm.provision "shell", inline: <<-SHELL
#      echo "192.168.56.20 client" >> /etc/hosts
#      apt-get --yes update
#      apt-get --yes dist-upgrade
#      apt-get --yes install vim iperf3 valgrind docker.io linux-tools-common linux-tools-generic pylint lldpd
#      if [[ $(lsb_release -cs) =~ focal ]] ; then
#          apt-get --yes install linux-generic-hwe-20.04
#      fi
#      apt-get --yes autoremove
#      adduser vagrant docker
#      # For xdp_sampler testing
#      mkdir -p /oc/local/config/
#      echo moo > /oc/local/config/srvtype
#      echo 'export INTERFACE=enp0s8' > /etc/profile.d/xdp_test_env.sh
#      echo 'export BUILD_PATH=/vagrant/build' >> /etc/profile.d/xdp_test_env.sh
#      /vagrant/build.sh -i
#    SHELL
#
#    # vagrant plugin install vagrant-reload
#    server.vm.provision :reload
#  end

  config.vm.define "client" do |client|
    client.vm.box = "ubuntu/jammy64"
    client.vm.hostname = "client"
    client.vm.network "private_network", ip: "192.168.56.20", hostname: true

    client.vm.provision "shell", inline: <<-SHELL
      echo "192.168.56.10 server" >> /etc/hosts
      apt-get --yes update
      apt-get --yes dist-upgrade
      apt-get --yes install vim iperf3 build-essential libssl-dev
      apt-get --yes autoremove
    SHELL
  end
end
