# PermissionsBoundary-Sample





デプロイ
```shell
cd terraform
terraform init

terraform fmt
terraform validate
terraform plan

terraform apply -auto-approve

```

テスト

```shell
./test_tool/test.py --profile pbtest

./test_tool/test.py --debug --profile pbtest
```s