# Bluecorp Order Processing - Python HTTP Azure Function

## Overview
This repository contains a Python-based HTTP Azure Function designed to handle order processing for Bluecorp. The function accepts a JSON payload containing order data, maps it to a CSV file format, and securely uploads the file to a third-party SFTP site. To ensure the files are not duplicated or sent across twice, an Azure Table is used to track the control numbers of processed orders and prevent duplicate dispatches.

![Current Architecture](resources/images/bluecorp-dispatch-order-Page-1)

## Features
- Accepts JSON payload via an HTTP POST request.
- Maps the JSON payload to a specific CSV format.
- Uploads the generated CSV file to a third-party SFTP site.
- Ensures duplicate orders (based on control numbers) are not processed twice using Azure Table Storage.
- For testing with an sftp site, I had created an extra blob storage account with SFTP enabled to test the public key authenticated and sftp upload

## Features Not Completed
- Integrations must recover gracefully on transient errors such as SFTP site temporarily unavailable
- Application Insights not enabled
- Enabling public whitelisting
- While there are some azure infrastructure deployed via Azure DevOps pipeline, there is an issue with deploying the functions within the function app. Function runs locally however it is not deploying correctly via the pipelines

# Challenges faced
- Due to restrictions on a free Azure Devops account, I had setup a self-hosted agent for Windows for the devops pipelines to execute. Majority of the time was spent debugging and setting this up
- Majority of the time was spent debugging on why the functions within the function app wasn't being deployed as the deplyment pipeline would show success but manual checks in Azure Portal showed the function itself is not available due to requirements packagaes not imported correctly or the functions not being defined well.

# If I have more time, I would have:
- worked on fixing the deployment pipeline to fix the functions not showing in Azure Portal
- worked on the features not completed
- Additional to the requirements, if I had more time, I would have used azure queues for implementing the retry mechanism and handling of failed dispatch orders. I would have also added a load balancer to handle higher traffic and ensure a better distribution of incoming requests.

![Future Architecture](resources/images/bluecorp-dispatch-order-Page-2)

## Prerequisites
1. **Azure Account**: Ensure you have access to an Azure account.
2. **Azure Resources**:
   - Azure Function App
   - Azure Storage Account with Table Storage enabled
3. **Third-Party SFTP Credentials**: Obtain the hostname, username, and password/private key for the SFTP server.
4. **Development Environment**:
   - Python 3.11+
   - Azure Functions Core Tools
   - Visual Studio Code with Azure Functions and Python extensions installed

## Getting Started

### Setup and Configuration

1. **Clone the Repository**:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Install Dependencies**:
   Create a virtual environment and install the required packages.
   ```bash
   python -m venv .env
   source .env/bin/activate  # On Windows, use .env\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Set Up Local Settings**:
   Update the `local.settings.json` file with the following configurations:
   ```json
   {
       "IsEncrypted": false,
       "Values": {
           "AzureWebJobsStorage": "<Your_Azure_Storage_Connection_String>",
           "FUNCTIONS_WORKER_RUNTIME": "python",
           "SFTP_HOST": "<SFTP_Host>",
           "SFTP_USERNAME": "<SFTP_Username>",
           "SFTP_PASSWORD": "<SFTP_Password>",
           "TABLE_NAME": "<Azure_Table_Name>",
           "STORAGE_ACCOUNT_NAME": "<Storage_Account_Name>",
           "STORAGE_ACCOUNT_KEY": "<Storage_Account_Key>"
       }
   }
   ```

4. **Deploy Azure Resources**:
   Use Bicep templates or Azure CLI to deploy required Azure resources, such as the Function App and Storage Account.

5. **Run the Function Locally**:
   ```bash
   func start
   ```
   The function will be available at `http://localhost:7071/api/<function_name>`.

### JSON Payload Format
The schema for the JSON data is at resources\schema directory

### CSV Output Format
The generated CSV will have the following columns:
```
ControlNumber,OrderDate,CustomerName,ItemName,Quantity,Price
```

### Deployment to Azure
1. **Deploy Using Azure Functions Core Tools**:
   ```bash
   func azure functionapp publish <FunctionApp_Name>
   ```

### Azure Table Storage Schema
The Azure Table is used to track processed control numbers and has the following schema:
- **PartitionKey**: Fixed value (e.g., `DispatchOrder` if successfully uploaded or `FailedUploads` if unsuccessful)
- **RowKey**: Control number (unique identifier for each order)
- **FileContent**: File in case of failure to upload to SFTP site
- **Timestamp**: Automatically generated by Azure Table Storage

### Error Handling
- If an order with the same control number is received, the function logs a message regarding having received a duplicate order and does not reprocess the order.
- Any issues with SFTP uploads or Azure Table operations are logged for debugging.


## Testing
1. **Unit Tests** (This is not yet implemented):
   Run the included unit tests using `pytest`:
   ```bash
   pytest tests/
   ```

2. **End-to-End Testing**:
   Use tools like Postman or curl to send sample JSON payloads to the function.

