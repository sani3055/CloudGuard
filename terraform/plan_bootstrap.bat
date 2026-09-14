@echo off
terraform plan -target=aws_ecr_repository.lambda_repo -target=aws_iam_openid_connect_provider.github -target=aws_iam_role.github_actions -target=aws_iam_role_policy.github_actions -out=bootstrap.tfplan
