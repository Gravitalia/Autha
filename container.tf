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
    image  = "ghcr.io/gravitalia/autha:3.0.0"
    cpu    = 0.5
    memory = 1

    ports {
      port     = 80
      protocol = "TCP"
    }

    volume {
      name                 = "config"
      mount_path           = "/"
      read_only            = true
      share_name           = azurerm_storage_share.gravitalia.name
      storage_account_name = azurerm_storage_account.gravitalia.name
      storage_account_key  = azurerm_storage_account.gravitalia.primary_access_key
    }

    environment_variables = {
      MEMORY_COST = 8192
      ROUND       = 1
      HASH_LENGTH = 16
    }

    secure_environment_variables = {
      CHACHA20_KEY = "4D6A514749614D6C74595A50756956446E5673424142524C4F4451736C515233"
      AES256_KEY   = "4D6a514749614D6c74595a50756956446e5673424142524c4f4451736c515233"
      KEY          = "SECRET"
    }
  }
}
