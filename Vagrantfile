# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

unless Vagrant.has_plugin?("vagrant-hostmanager")
  raise 'vagrant-hostmanager is not installed! '\
        'Please run: vagrant plugin install vagrant-hostmanager'
end

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "rubicon/ubuntu1404-salt"
  config.vm.synced_folder "salt/roots/", "/srv/"

  config.hostmanager.enabled = true
  config.hostmanager.manage_host = false

  config.vm.provision :salt do |salt|
    salt.log_level = "error"
    salt.minion_config = "salt/minion"
    salt.run_highstate = true
  end

  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
  end

  config.vm.define "elasticsearch" do |elasticsearch|
    elasticsearch.vm.hostname = "elasticsearch"
  end

  config.vm.define "elastalert" do |elastalert|
    elastalert.vm.hostname = "elastalert"
  end

  config.vm.provision :shell, :inline => "/usr/games/cowsay $HOSTNAME is ready!"
end
