terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>2.0"
    }
    azuread = {
      source = "hashicorp/azuread"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "gravitalia" {
  location = "North Europe"
  name     = "Gravitalia"
}

resource "azurerm_storage_account" "gravitalia" {
  name                     = "gravitalia"
  resource_group_name      = azurerm_resource_group.gravitalia.name
  location                 = azurerm_resource_group.gravitalia.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_share" "gravitalia" {
  name                 = "gravitalia-share"
  storage_account_name = azurerm_storage_account.gravitalia.name
  quota                = 1
}

resource "azurerm_storage_share_file" "gravitalia" {
  name             = "config.yaml"
  storage_share_id = azurerm_storage_share.gravitalia.id
  source           = "config.yaml"
}

resource "azurerm_container_group" "gravitalia" {
  name                = "autha"
  location            = azurerm_resource_group.gravitalia.location
  resource_group_name = azurerm_resource_group.gravitalia.name
  restart_policy      = "Never"
  ip_address_type     = "Public"
  dns_name_label      = "gravitalia"
  os_type             = "Linux"

  container {
    name   = "autha"
    image  = var.image
    cpu    = var.cpu_cores
    memory = var.memory_in_gb

    ports {
      port     = var.port
      protocol = "TCP"
    }

    volume {
      name                 = "config"
      mount_path           = "/config/"
      read_only            = true
      share_name           = azurerm_storage_share.gravitalia.name
      storage_account_name = azurerm_storage_account.gravitalia.name
      storage_account_key  = azurerm_storage_account.gravitalia.primary_access_key
    }

    environment_variables = {
      MEMORY_COST = var.argon2_memory_cost
      ROUND       = var.argon2_round
      HASH_LENGTH = var.argon2_hash_length
      CONFIG_PATH = "./config/config.yaml"
    }

    secure_environment_variables = {
      CHACHA20_KEY = var.chacha20_key
      AES256_KEY   = var.aes_key
      KEY          = var.argon2_key
    }
  }
}
