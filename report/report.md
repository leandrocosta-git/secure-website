# PLANO

Day 1: Project Setup & Static Website

    ✅ Tasks:

        Create GitHub repo (secure-static-site) ✅

        Choose a static website template (HTML/CSS/JS) ✅

        Set up S3 bucket (secure-static-site-prod)✅

            Enable static website hosting ✅

            Block all public access (you'll use CloudFront) ✅

Developer (write-only)        Upload your website manually ✅

    🛡️ Security Focus:

        Ensure the S3 bucket has no public access (not even GetObject)

Day 2: IAM & Least Privilege

    ✅ Tasks:

        Create IAM policies for:

            Developer (write-only) ✅

            CI/CD role (limited PutObject, ListBucket) ✅

            Viewer role (for logs, read-only) ✅

        Create IAM roles with attached policies ✅

    🛡️ Security Focus:

        Use IAM policy conditions (e.g., aws:SourceIp, aws:UserAgent)

        Test that incorrect permissions fail

Day 3: Automation with GitHub Actions

    ✅ Tasks:

        Create GitHub Action for:

            Linting HTML/CSS

            Deploying to S3 with OIDC (no hardcoded credentials)

        Setup OpenID Connect between GitHub and AWS

    🛡️ Security Focus:

        No AWS secrets in repo!

        Use sts:AssumeRoleWithWebIdentity with Condition: StringEquals: "token.actions.githubusercontent.com:aud"

Day 4: CloudFront & TLS

    ✅ Tasks:

        Create CloudFront distribution in front of S3 bucket

        Request a free TLS cert via ACM

        Restrict S3 access to CloudFront (Origin Access Control or Legacy OAI)

    🛡️ Security Focus:

        Enforce HTTPS-only

        Add WAF (optional) to protect against basic attacks (SQLi, XSS patterns)

Day 5: Logging & Monitoring

    ✅ Tasks:

        Enable CloudTrail for all management events

        Enable S3 access logs to a separate bucket

        Enable CloudFront access logs

        Enable GuardDuty

    🛡️ Security Focus:

        Add alerts (e.g., GuardDuty findings via SNS or EventBridge)

Day 6: Harden Everything

    ✅ Tasks:

        Add CSP, X-Frame-Options, X-XSS-Protection headers via CloudFront

        Enable versioning and MFA delete on S3

        Use bucket policies with aws:Referer or aws:UserAgent (if useful)

    🛡️ Security Focus:

        Least privilege for every service

        No unauthenticated access

        Zero hardcoded secrets

Day 7: Documentation & CV Integration

    ✅ Tasks:

        Create a detailed README.md:

            Diagram of the architecture

            IAM policies used

            GitHub Actions workflow

            Security measures taken

            Monitoring setup

        Push everything to GitHub

        Add to your CV: “Secure static website on AWS with S3, IAM, GitHub Actions, CloudFront, GuardDuty”


# EXECUCAO

## day1
buscar template de site

criar bucket s3 
- secure-website-lrccosta
regiao eu-west-2
permissions > Block public access 

mandar site para o bucket
```aws s3 cp ./site/ s3://secure-website-lrccosta/ --recursive```

ver armazenamento usado pelos objetos
```aws s3 ls s3://secure-website-lrccosta --recursive --human-readable --summarize```

## day2
adicionei um identity proveiver para github para futuramente usar actions
```
Provider Type	OIDC
Provider URL	https://token.actions.githubusercontent.com
Audience	sts.amazonaws.com
```

criar roles
- Developer
- Reader

Web Identity usada na criaçao dos roles
- Identity provider e Audience definida anteriormente
- GitHub organization : leandrocosta-git (me)
- GitHub repo: the one we using

Politica para o role de CI/CD
- Name: S3SecureStaticSiteDeploy
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowDeployToS3",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::secure-website-lrccosta",
        "arn:aws:s3:::secure-website-lrccosta/*"
      ]
    }
  ]
}
```

Politica de Viewer
- Name: S3SecureStaticSiteReadOnly
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::secure-website-lrccosta/*"
    }
  ]
}
```

Politica de Developer
- Name: S3SecureStaticSiteWriteOnly
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteOnlyFromIPv6",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::secure-website-lrccosta/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "REDACTED:/128"
        },
        "StringLike": {
          "aws:UserAgent": "*cloudsec-deployer*"
        }
      }
    }
  ]
}
```
inclui uma politica que limita o acesso a um certo ip e a uma certa role


defini IAM roles
- SecureStaticSiteCICDRole: cloudsec-deployer(CI/CD)
- viewer:
- Developer (write-only): 

e associar à policy definida anteriormente

Na role `user` defini a minha conta root da AWS como root da role viewer sabendo que não é a implementação mais segura. Tenho intençoes de mudar futuramente.
```
"Principal": {
  "AWS": "arn:aws:iam::<account_id>:root"
}
```
Faço esta implementação por se tratar de um projeto individual num ambiente controlado, tratando-se de algo temporário. Alem disso esta role segue os principios de `least privilege`.
- AINDA ASSIM REVER SE FOR DEPLOYED!!
- Possivel problemas de Confused Deputy

posteriormente meti
```
"Principal": {
  "AWS": "arn:aws:iam::017820667577:user/cloudsec-deployer"
}
```

para o Developer (write-only) defini:
```
"Principal": {
        "AWS": "arn:aws:iam::017820667577:user/cloudsec-deployer"
      }
```

vi as security credentials deste user `cloudsec-deployer` para poder utilizar a AWS CLI.
- acess key ID: AKIAQIJRRZ...REDACTED
- Secret access key: rfAWaGr0GYu.....REDACTED

Fui testar as politicas usando
https://policysim.aws.amazon.com/

Por exemplo, nesta imagem, vemos que a role ReadOnly nao tem permissoes de GetObject nem PutObject.

![AWS Policy Simulator showing ReadOnly role denied GetObject and PutObject permissions](./images/test_policy_readonly.png)

Verifiquei o comportamento das roles criadas que se comportam como esperado.

## day3
criei a github action .github/workflows/deploy.yml
```
name: Deploy static site to S3

on:
  push:
    branches:
      - main  # ou a branch que usas

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Lint HTML/CSS
        uses: cyb10101/htmlhint-action@v1

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::017820667577:role/SecureStaticSiteCICDRole
          aws-region: eu-west-1

      - name: Deploy static site to S3
        run: aws s3 sync ./site/ s3://secure-website-lrccosta/ --delete
```
