#Se configura azure como proveedor
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "=3.0.0"
    }
  }
}

#Se configura azure como proveedor
provider "azurerm" {
  features {}
}

#Creación del grupo de Trabajo
resource "azurerm_resource_group" "proyecto_arnid" {
  name     = "proyecto_arnid"
  location = "West Europe"
}

#Red Virtual de arnid
resource "azurerm_virtual_network" "World" {
  name                = "Arnid"
  address_space       = ["172.16.0.0/16"]
  location            = azurerm_resource_group.proyecto_arnid.location
  resource_group_name = azurerm_resource_group.proyecto_arnid.name
}

#Subnet Red Interna
resource "azurerm_subnet" "interna" {
  name                 = "Interna_principal"
  resource_group_name  = azurerm_resource_group.proyecto_arnid.name
  virtual_network_name = azurerm_virtual_network.World.name
  address_prefixes     = ["172.16.20.0/24"]
}

#IP pública de Debian
resource "azurerm_public_ip" "publica_Debian" {
  name                = "Ip-publica-Debian"
  location            = "West Europe"
  resource_group_name = azurerm_resource_group.proyecto_arnid.name
  allocation_method   = "Static"
}

#IP pública de Ubuntu
resource "azurerm_public_ip" "publica_Ubuntu" {
  name                = "Ip-publica-Ubuntu"
  location            = "West Europe"
  resource_group_name = azurerm_resource_group.proyecto_arnid.name
  allocation_method   = "Static"
}

#Tarjeta de Red de Debian
resource "azurerm_network_interface" "tarjeta" {
  name                = "Tarjeta-red-Debian"
  location            = azurerm_resource_group.proyecto_arnid.location
  resource_group_name = azurerm_resource_group.proyecto_arnid.name

  ip_configuration {
    name                          = "Interna-Debian"
    subnet_id                     = azurerm_subnet.interna.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.publica_Debian.id
  }
}

#Tarjeta de Red de Ubuntu
resource "azurerm_network_interface" "Interfaz" {
  name                = "Tarjeta-red-Ubuntu"
  location            = azurerm_resource_group.proyecto_arnid.location
  resource_group_name = azurerm_resource_group.proyecto_arnid.name

  ip_configuration {
    name                          = "Interna-Ubuntu"
    subnet_id                     = azurerm_subnet.interna.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.publica_Ubuntu.id
  }
}

#Firewall de Debian
resource "azurerm_network_security_group" "firewall_Debian" {
  name                = "grupo-seguridad-Debian"
  location            = azurerm_resource_group.proyecto_arnid.location
  resource_group_name = azurerm_resource_group.proyecto_arnid.name
#creamos las reglas del firewall para los distintos servicios con la siguiente estructura:
  security_rule {
    name                       = "ssh_Debian"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "nginx_tcp"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "streaming_udp"
    priority                   = 102
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "1935"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "streaming_tcp"
    priority                   = 103
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1935"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "https_Debian"
    priority                   = 104
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Zabbix_puerto1"
    priority                   = 106
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "10050"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Zabbix_puerto2"
    priority                   = 107
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "10051"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "MySql"
    priority                   = 108
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "zabbix_82"
    priority                   = 109
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "82"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
    security_rule {
    name                       = "DNS_udp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
    security_rule {
    name                       = "DNS_tcp"
    priority                   = 111
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

#Asociamos la interfaz de red con el firewall de la maquina
resource "azurerm_network_interface_security_group_association" "firewall_debian_asociación" {
  network_interface_id      = azurerm_network_interface.tarjeta.id
  network_security_group_id = azurerm_network_security_group.firewall_Debian.id
}

#Firewall de Ubuntu
resource "azurerm_network_security_group" "firewall_Ubuntu" {
  name                = "grupo-seguridad-Ubuntu"
  location            = azurerm_resource_group.proyecto_arnid.location
  resource_group_name = azurerm_resource_group.proyecto_arnid.name

#creamos las reglas del firewall con la siguiente estructura:
  security_rule {
    name                       = "ssh_Ubuntu"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "apache_Ubuntu"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "streaming_udp"
    priority                   = 102
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "1935"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "streaming_tcp"
    priority                   = 103
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1935"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "https_ubuntu"
    priority                   = 104
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
     security_rule {
    name                       = "smtp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "25"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
   security_rule {
    name                       = "imap"
    priority                   = 111
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "993"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
   security_rule {
    name                       = "voz_ip_tcp"
    priority                   = 112
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5060"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
   security_rule {
    name                       = "voz_ip_udp"
    priority                   = 113
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "5060"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
   security_rule {
    name                       = "voz_ip_asterix2"
    priority                   = 114
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5062"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
    security_rule {
    name                       = "voz_ip_asterix"
    priority                   = 115
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "5062"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Zabbix_puerto1"
    priority                   = 116
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "10050"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Zabbix_puerto2"
    priority                   = 117
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "10051"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "MySql"
    priority                   = 118
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
    security_rule {
    name                       = "zabbix_cosas"
    priority                   = 119
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "82"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
    security_rule {
    name                       = "DNS_udp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
    security_rule {
    name                       = "DNS_tcp"
    priority                   = 111
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

#Unión de la Interfaz de Red con las reglas de Firewall
resource "azurerm_network_interface_security_group_association" "firewall_ubuntu_asociación" {
  network_interface_id      = azurerm_network_interface.Interfaz.id
  network_security_group_id = azurerm_network_security_group.firewall_Ubuntu.id
}

#Primera Máquina Debian
resource "azurerm_linux_virtual_machine" "Debian" {
  name                = "Debian-Server"
  resource_group_name = azurerm_resource_group.proyecto_arnid.name
  location            = azurerm_resource_group.proyecto_arnid.location
  size                = "Standard_B2s"
  admin_username      = "Carlos"
  network_interface_ids = [
    azurerm_network_interface.tarjeta.id,
  ]
#Asignamos nuestra clave publica a nuestra máquina
  admin_ssh_key {
    username   = "Carlos"
    public_key = file("~/.ssh/id_rsa.pub")
  }
#Creamos el disco para la maquina
  os_disk {
    name                 = "Debian_Disco"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
#Le asignamos el SO a nuestra máquina
  source_image_reference {
    publisher = "debian"
    offer     = "debian-11"
    sku       = "11"
    version   = "latest"
  }
# Realizamos una conexión mediante ssh, para que ejecuta el comando "echo Done" y nos indique que hay IP publica en nuestra maquina.
      provisioner "remote-exec" {
  inline = ["echo Done!"]
    connection {
      type        = "ssh"
      host        =  "${azurerm_public_ip.publica_Debian.ip_address}"
      user        = "Carlos"
      port        = 22 
      timeout     = "1m" 
      agent       = false 
      private_key = file("./id_rsa")
    }
  }
#Una vez confirmado que nuestra maquina tiene IP publica realizamos en nuestro equipo el aprovisionamiento con "Ansible".
  provisioner "local-exec" {
        command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u Carlos --private-key ./id_rsa -i '${azurerm_public_ip.publica_Debian.ip_address},' playbookDebian.yml"
    }
}

#Segunda máquina Ubuntu
resource "azurerm_linux_virtual_machine" "Ubuntu" {
  name                = "Ubuntu-server"
  resource_group_name = azurerm_resource_group.proyecto_arnid.name
  location            = azurerm_resource_group.proyecto_arnid.location
  size                = "Standard_B2s"
  admin_username      = "Daniel"
  network_interface_ids = [
    azurerm_network_interface.Interfaz.id,
  ]
#Asignamos nuestra clave publica a nuestra máquina
  admin_ssh_key {
    username   = "Daniel"
    public_key = file("./id_rsa.pub")
  }
#Creamos el disco para la maquina
  os_disk {
    name                 = "Ubuntu_Disco"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
#Le asignamos el SO a nuestra máquina
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts"
    version   = "latest"    
  }
# Realizamos una conexión mediante ssh, para que ejecuta el comando "echo Done" y nos indique que hay IP publica en nuestra maquina.
    provisioner "remote-exec" {
      inline = ["echo Done!"]
    connection {
      type        = "ssh"
      host        = "${azurerm_public_ip.publica_Ubuntu.ip_address}"
      user        = "Daniel"
      port        = 22 
      timeout     = "1m" 
      agent       = false 
      private_key = file("./id_rsa")
    }
  }
#Una vez confirmado que nuestra maquina tiene IP publica realizamos en nuestro equipo el aprovisionamiento con "Ansible".
    provisioner "local-exec" {
      command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u Daniel --private-key ./id_rsa -i '${azurerm_public_ip.publica_Ubuntu.ip_address},' playbookUbuntu.yml"
  }
}

#necesitamos para lanzar la VPN crear los certificados autofirmados con el siguiente comando en powershell:
#$cert = New-SelfSignedCertificate -Type Custom -Keyspec Signature `
#-Subject "CN=Arnid" -KeyExportPolicy Exportable `
#-HashAlgorithm sha256 -KeyLength 2048 `
#-CertStoreLocation "Cert:\CurrentUser\My" -KeyUsageProperty Sign -KeyUsage CertSign
#
#New-SelfSignedCertificate -Type Custom -DnsName P2SChildCert -KeySpec Signature `
#-Subject "CN=cliente-Arnid" -KeyExportPolicy Exportable `
#-CertStoreLocation "Cert:\CurrentUser\My" `
#-Signer $cert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")

#Realizamos la creacion de IP publica 
   resource "azurerm_public_ip" "publica_gateway" {
      name                         = "ip-publica-gateway"
      location                     = "West Europe"
      resource_group_name          = azurerm_resource_group.proyecto_arnid.name
    allocation_method            = "Dynamic"
   }
#Indicamos la subnet en la que se creara la gateway
    resource "azurerm_subnet" "gateway" {
      name                 = "GatewaySubnet"
      resource_group_name  = azurerm_resource_group.proyecto_arnid.name
    virtual_network_name = azurerm_virtual_network.World.name
     address_prefixes     = ["172.16.0.0/24"]
    }
    
#Configuramos la gateway 
    resource "azurerm_virtual_network_gateway" "gateway" {
      name                = "Arnid-VPN"
      location            = azurerm_resource_group.proyecto_arnid.location
      resource_group_name = azurerm_resource_group.proyecto_arnid.name
    
     type     = "Vpn"
      vpn_type = "RouteBased"
    
      active_active = false
      enable_bgp    = false
      sku           = "Basic"
    
      ip_configuration {
        name                          = "vnetGatewayConfig"
        public_ip_address_id          = azurerm_public_ip.publica_gateway.id
        private_ip_address_allocation = "Dynamic"
        subnet_id                     = azurerm_subnet.gateway.id
      }
#Indicamos el rango de IP que tendran nuestros clientes en el tunnel para acceder a la red.   
      vpn_client_configuration {
        address_space = ["10.30.0.0/24"]
#Nombre del certificado que aparecera en el servidor VPN de Azure    
        root_certificate {
          name = "Arnid-CA"
#Añadimos el certificado Root    
          public_cert_data = <<EOF
MIIC2zCertificado

    EOF
        }
      }
    }                                                       
