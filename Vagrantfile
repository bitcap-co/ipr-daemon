# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://vagrantcloud.com/search.
  config.vm.box = "freebsd/FreeBSD-14.0-CURRENT"
  config.vm.box_version = "2023.08.03"
  config.vm.guest = :freebsd
  config.ssh.shell = "sh"
  config.vm.provision "shell", inline: <<-SHELL
    pkg install -y binutils git gmake go libpcap virtualbox-ose-kmod \
      virtualbox-ose-additions-nox11 aarch64-gcc13 \
      aarch64-binutils arm-gnueabi-binutils amd64-binutils \
      armv7-freebsd-sysroot aarch64-freebsd-sysroot
  SHELL


  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # NOTE: This will enable public access to the opened port
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine and only allow access
  # via 127.0.0.1 to disable public access
  # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Disable the default share of the current code directory. Doing this
  # provides improved isolation between the vagrant box and your host
  # by making sure your Vagrantfile isn't accessible to the vagrant box.
  # If you use this you may want to enable additional shared subfolders as
  # shown above.
  config.vm.synced_folder ".", "/home/vagrant/ipr-daemon", create: true, disabled: false, id: 'source-code', type: 'rsync'

  config.vm.provider :virtualbox do |vb|
    vb.name = "ipr-daemon-freebsd"
    vb.gui = false
    vb.customize ["modifyvm", :id, "--vram", "16", "--graphicscontroller", "vmsvga"]
    vb.cpus = 2
    vb.memory = 1024
  end
  config.trigger.after :up do |trigger|
    trigger.info = "building pfSense/FreeBSD binary..."
    trigger.name = "build-binary"
    trigger.run = {inline: "vagrant rsync"}
    trigger.run_remote = {inline: "sh -c 'PATH=/usr/local/bin:${PATH} cd ipr-daemon && gmake freebsd-binaries'"}
  end
end
