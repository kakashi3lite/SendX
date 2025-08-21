# SendX Cloud Deployment Guide

This guide provides instructions for deploying SendX to various cloud platforms.

## Prerequisites

- Docker installed on your local machine
- Git repository access
- Cloud provider account (choose one):
  - Google Cloud Platform
  - Amazon Web Services (AWS)
  - Microsoft Azure
  - Heroku

## Deployment Options

### Option 1: Google Cloud Run (Recommended for Simplicity)

1. **Install Google Cloud SDK**:
   - Download and install from: https://cloud.google.com/sdk/docs/install

2. **Authenticate and set up a project**:
   ```bash
   gcloud auth login
   gcloud projects create sendx-production --name="SendX Production"
   gcloud config set project sendx-production
   ```

3. **Enable required services**:
   ```bash
   gcloud services enable cloudbuild.googleapis.com
   gcloud services enable run.googleapis.com
   ```

4. **Set up Redis on Google Cloud Memorystore** (optional for persistence):
   ```bash
   gcloud services enable redis.googleapis.com
   gcloud redis instances create sendx-redis --size=1 --region=us-central1 --tier=basic
   ```
   - Note the Redis endpoint after creation

5. **Build and deploy**:
   ```bash
   # Build the container
   gcloud builds submit --tag gcr.io/sendx-production/sendx:latest

   # Deploy to Cloud Run
   gcloud run deploy sendx \
     --image gcr.io/sendx-production/sendx:latest \
     --platform managed \
     --allow-unauthenticated \
     --region us-central1 \
     --set-env-vars="STORAGE_TYPE=redis,REDIS_URL=redis://REDIS_IP:6379"
   ```

6. **Access your deployed application**:
   - The deployment command will output a URL where your application is accessible

### Option 2: AWS Elastic Container Service (ECS)

1. **Install AWS CLI**:
   - Download and install from: https://aws.amazon.com/cli/

2. **Configure AWS credentials**:
   ```bash
   aws configure
   ```

3. **Create an ECR repository**:
   ```bash
   aws ecr create-repository --repository-name sendx
   ```

4. **Build and push the Docker image**:
   ```bash
   # Login to ECR
   aws ecr get-login-password | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

   # Build and tag the image
   docker build -t sendx .
   docker tag sendx:latest $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/sendx:latest

   # Push the image
   docker push $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/sendx:latest
   ```

5. **Create an ECS cluster and service**:
   - Use the AWS Console to create an ECS cluster
   - Create a task definition using the ECR image
   - Launch a service on the cluster

### Option 3: Heroku (Simplest for Testing)

1. **Install Heroku CLI**:
   - Download and install from: https://devcenter.heroku.com/articles/heroku-cli

2. **Login and create app**:
   ```bash
   heroku login
   heroku create sendx-app
   ```

3. **Add Redis add-on**:
   ```bash
   heroku addons:create heroku-redis:hobby-dev
   ```

4. **Deploy using Heroku Container Registry**:
   ```bash
   # Login to Heroku Container Registry
   heroku container:login

   # Build and push the image
   heroku container:push web -a sendx-app

   # Release the image
   heroku container:release web -a sendx-app
   ```

5. **Open the app**:
   ```bash
   heroku open -a sendx-app
   ```

## Production Considerations

### Security
- Enable HTTPS for all communication
- Set a strong SECRET_KEY environment variable
- Consider adding a Web Application Firewall (WAF)

### Scalability
- Set up auto-scaling based on load
- Use a managed Redis service with appropriate capacity
- Configure proper CPU and memory allocation

### Monitoring
- Set up logging with a service like Stackdriver, CloudWatch, or Azure Monitor
- Implement application performance monitoring
- Set up alerts for error rates and performance issues

### Backup and Disaster Recovery
- Configure regular Redis backups
- Set up a disaster recovery plan
- Test restoration procedures regularly

## Maintenance

### Updates
1. Make code changes locally and test
2. Rebuild Docker image with a new tag
3. Push to container registry
4. Update the deployment to use the new image

### Rollbacks
If an update causes issues, roll back to the previous version using your cloud provider's rollback mechanism or by redeploying the previous image tag.

## Support and Troubleshooting

For issues with deployment, consult:
- Your cloud provider's documentation
- The logs of your deployed application
- The SendX support resources
