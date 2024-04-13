variable "image" {
  type        = string
  description = "Container image to deploy. Should be of the form repoName/imagename:tag for images stored in public Docker Hub, or a fully qualified URI for other registries. Images from private registries require additional registry credentials."
  default     = "ghcr.io/gravitalia/autha:3.0.0"
}

variable "port" {
  type        = number
  description = "Port to open on the container and the public IP address."
  default     = 80
}

variable "cpu_cores" {
  type        = number
  description = "The number of CPU cores to allocate to the container."
  default     = 0.5
}

variable "memory_in_gb" {
  type        = number
  description = "The amount of memory to allocate to the container in gigabytes."
  default     = 1
}

variable "argon2_memory_cost" {
  type        = number
  description = "The amount of memory used to hash the user's password. Higher is better. Higher is coster."
  default     = 65536
}

variable "argon2_round" {
  type        = number
  description = "Number of iterations the Argon2 hash function undergoes during the password hashing process."
  default     = 2
}

variable "argon2_hash_length" {
  type        = number
  description = "Final hash size."
  default     = 32
}

variable "argon2_key" {
  type        = string
  description = "Private key for hasher with Argon2. This key is NOT used for decryption."
  default     = "SECRET"
}

variable "aes_key" {
  type        = string
  description = "AES256 key used to encrypt and decrypt format presverving encryption used for e-mails."
  default     = "4D6a514749614D6c74595a50756956446e5673424142524c4f4451736c515233"
}

variable "chacha20_key" {
  type        = string
  description = "ChaCha20-Poly1305 key used to encrypt and decrypt various type of datas."
  default     = "4D6A514749614D6C74595A50756956446E5673424142524C4F4451736C515233"
}
