# AWS Dashboard Configuration Guide

## Environment Variables for AWS Deployment

### Required Configuration

Set these environment variables on your AWS instance:

```bash
# API URL - Use your AWS instance public IP or domain
export SEMIO_API_URL="http://your-aws-instance-ip:8000"
# or
export SEMIO_API_URL="http://your-domain.com:8000"

# Dashboard Configuration (optional)
export SEMIO_DASHBOARD_HOST="0.0.0.0"  # Allow external connections
export SEMIO_DASHBOARD_PORT="7860"     # Dashboard port
```

### Example AWS Instance Setup

1. **Get your instance public IP:**
   ```bash
   curl http://169.254.169.254/latest/meta-data/public-ipv4
   ```

2. **Set environment variables:**
   ```bash
   export SEMIO_API_URL="http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
   ```

3. **Start the dashboard:**
   ```bash
   cd backend
   python app/dashboard.py
   ```

### Security Groups Configuration

Ensure your AWS security groups allow:
- **Port 8000**: For the Semio API
- **Port 7860**: For the Gradio dashboard

### Production Recommendations

1. **Use a domain name** instead of IP address
2. **Set up HTTPS** with SSL certificates
3. **Use environment files** for configuration
4. **Consider using AWS Elastic Beanstalk** for easier deployment

### Example .env file for AWS:

```env
# API Configuration
SEMIO_API_URL=http://your-domain.com:8000

# Dashboard Configuration  
SEMIO_DASHBOARD_HOST=0.0.0.0
SEMIO_DASHBOARD_PORT=7860

# Other Semio settings
GOOGLE_API_KEY=your_google_api_key
DEBUG=False
```

### Troubleshooting

- **Dashboard can't connect to API**: Check `SEMIO_API_URL` and security groups
- **External access blocked**: Ensure `SEMIO_DASHBOARD_HOST=0.0.0.0`
- **Port conflicts**: Change `SEMIO_DASHBOARD_PORT` if needed
