terraform {
  backend "local" {
    path = "terraform.tfstate"
  }

  # For remote state in team environments, comment out the local backend above
  # and uncomment this block. Replace with your actual S3 bucket name.
  # backend "s3" {
  #   bucket         = "my-cloudguard-terraform-state"
  #   key            = "cloudguard/prod/terraform.tfstate"
  #   region         = "ap-south-1"
  #   dynamodb_table = "terraform-lock"
  #   encrypt        = true
  # }
}
