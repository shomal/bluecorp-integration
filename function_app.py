import datetime
import azure.functions as func
import logging
import json
import os
import csv
import paramiko
from azure.core.exceptions import ResourceNotFoundError
from jsonschema import validate, ValidationError
from controllers.mappers import ContainerTypeMapper
from models.json_model import ReadyForDispatch
from models.cvs_model import CsvModel
#from azure.identity import DefaultAzureCredential
#from azure.keyvault.secrets import SecretClient
from azure.data.tables import TableServiceClient

MAX_PAYLOAD_SIZE_KB = 800

#Initialize the KeyVault client
#key_vault_url = os.getenv("AZURE_KEY_VAULT_URL")
#secret_name = os.getenv("VAULT_PRIVATE_KEY_SECRET_NAME")
#credential = DefaultAzureCredential()
#client =SecretClient(vault_url=key_vault_url, credential=credential)

#retrieve private key
#private_key = client.get_secret(secret_name).value

#SFTP Configuration
sftp_host = os.getenv("SFTP_HOST")
sftp_port = os.getenv("SFTP_PORT")
sftp_username = os.getenv("SFTP_USERNAME")
sftp_incoming_folder = os.getenv("SFTP_INCOMING_FOLDER")

#Azure Table Storage Configuration
table_connection_string = os.getenv("AzureWebJobsStorage")
table_name = os.getenv("AZURE_TABLE_NAME")

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
@app.function_name(name="dispatch_order")
@app.route(route="bluecorp_order_processing")
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Received the dispatch load request from D365.')

    try:
        req_body = req.get_json()
        file_size_in_kb = len(req_body)

        if file_size_in_kb > MAX_PAYLOAD_SIZE_KB:
            return func.HttpResponse(f"The size of the payload is too large. Maximum allowed is {MAX_PAYLOAD_SIZE_KB} KB", status_code=413)
        
        logging.info(f"Dispatch payload received: {json.dumps(req_body, indent=4)}")
        schema_path = os.path.join("resources", "schema", "ready-for-dispatch-event-schema.json")
        logging.info("Validating JSON schema")

        validate_json(req_body, schema_path)

        dispatch_data = ReadyForDispatch(**req_body)

        #initialize table storage client
        table_service_client = TableServiceClient.from_connection_string(table_connection_string)
        table_client = table_service_client.get_table_client(table_name)

        logging.info(f"Dispatch Data: {dispatch_data}")
        
        #check for duplicate order/ control number
        control_number = dispatch_data.controlNumber
        if check_duplicate_order(table_client, control_number):
            logging.info(f"Duplicate order found for ControlNumber: {control_number}. This dispatch load will be skipped for processing.")
            return func.HttpResponse("Duplicate order found. No new payload to process.", status_code=200)

        #map the json data to csv
        mapped_csv_data = map_json_to_csv(dispatch_data)
        logging.info("Dispatch data mapped to CSV.")
        #logging.info(f"CSV data: {mapped_csv_data}")

        #write to csv file
        output_file = "dispatch_data.csv"
        write_to_csv_file(mapped_csv_data, output_file)
        logging.info(f"Dispatch data written to CSV file {output_file}")

            
        with open("bluecorp_rsa_id", "r") as key_file:
            private_key = key_file.read()

        #connect to SFTP server
        sftp_client = connect_to_SFTP(private_key)

        #upload the csv file to SFTP server
        upload_to_SFTP(sftp_client, output_file, control_number)

        insert_processed_order(table_client, control_number)
        logging.info(f"Order with ControlNumber: {control_number} processed successfully")

        #cleanup the csv file
        os.remove(output_file)

        return func.HttpResponse("Dispatch Payload processed successfully", status_code=200)
    
    except ValueError as e:
        logging.error(f"Invalid JSON Payload: {e}")
        return func.HttpResponse(
            "Invalid dispatch JSON Payload. Please check your input.", status_code=400)
    except ValidationError as e:
        logging.error(f"JSON schema validation failed, {e.message}")
        return func.HttpResponse(f"JSON validation failed: {e.message}", status_code=400)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return func.HttpResponse(
            "An error occurred while processing the dispatch payload.", status_code=500     )
        

def validate_json(json_data, schema_path):
    # Load the schema from the external JSON file and validate json data
    with open(schema_path, 'r') as file:
        schema = json.load(file)
        validate(instance=json_data, schema=schema)
        logging.info("JSON Schema validation passed")


def map_json_to_csv(json_data):
    #Map the json dispatch data to 3PL csv data 
    logging.info("Mapping dispatch json data to csv")

    csv_models = []
    for container in json_data.containers:
        for item in container.items:
            csv_model = CsvModel(
                customerReference=json_data.salesOrder,
                loadId=container.loadId,
                containerType=ContainerTypeMapper.map_container_type(container.containerType),
                itemCode=item.itemCode,
                itemQuantity=item.quantity,
                itemWeight=item.cartonWeight,
                street=json_data.deliveryAddress.street,
                city=json_data.deliveryAddress.city,
                state=json_data.deliveryAddress.state,
                postalCode=json_data.deliveryAddress.postalCode,
                country=json_data.deliveryAddress.country,
            )
            csv_models.append(csv_model)
    return csv_models


def write_to_csv_file(csv_models, file_path):
    # Write the csv data to the file
    logging.info("Writing the CSV data to the file")
    with open(file_path, mode='w', newline="") as file:
        writer = csv.writer(file)
        writer.writerow(csv_models[0].__dict__.keys())
        for csv_model in csv_models:
            writer.writerow(csv_model.__dict__.values())
    logging.info(f"CSV file created at: {file_path}")

def connect_to_SFTP(private_key):
    # Connect to the SFTP server
    logging.info("Starting private key transformation and SFTP connection")

    private_key = private_key.strip()

    #try:
        # Save private key to a temporary file
    temp_key_file = "temp_private_key.pem"
    with open(temp_key_file, "w") as key_file:
        key_file.write(private_key)
        
    # # Ensure correct file permissions
    os.chmod(temp_key_file, 0o600)  # Read and write for the owner only

    # Load the private key
    private_key_obj = paramiko.RSAKey.from_private_key_file(temp_key_file)

    logging.info("Connecting to SFTP server")
    # Establish the SFTP connection
    transport = paramiko.Transport((sftp_host, sftp_port))
    transport.connect(username=sftp_username, pkey=private_key_obj)
    sftp = paramiko.SFTPClient.from_transport(transport)
    logging.info("Connected to SFTP server")

    # Clean up the temporary private key file after connecting
    os.remove(temp_key_file)
    return sftp
    

def upload_to_SFTP(sftp_client, upload_path, control_number):
    # Upload the CSV file to the SFTP server
    logging.info("Uploading the CSV file to SFTP server")
    try:
        sftp_client.put("dispatch_data.csv", f"{sftp_incoming_folder}/{upload_path}")
        logging.info("CSV file uploaded to SFTP server")
    except Exception as e:
        logging.error(f"Failed to upload the CSV file to SFTP server: {e}")
        # Save file content to Azure Table Storage for retry
        with open("dispatch_data.csv", "r") as file:
            file_content = file.read()
            save_failed_upload_to_table(table_name, control_number, file)
        logging.info(f"File saved to Azure Table Storage for later retry: ControlNumber={control_number}")
        return func.HttpResponse(
            "Failed to upload the CSV file to SFTP server", status_code=500)
    finally:
        sftp_client.close()
        logging.info("SFTP connection closed")


def check_duplicate_order(table_client, control_number):
    # Check if the order with the control number already exists in the table
    control_number = str(control_number)
    logging.info(f"Checking for existing orders in the table with control number: {control_number}")
    try:
        entity = table_client.get_entity(partition_key="DispatchOrder", row_key=control_number)
        if entity:
            return True  # Duplicate order found
    except ResourceNotFoundError:
        logging.info(f"No existing order found for ControlNumber so will proceed with processing this dispatch: {control_number}")
        return False
    except Exception as e:
        logging.error(f"Failed to check for duplicate orders: {e}")	
        return False
    
def insert_processed_order(table_client, control_number):
    # Insert the processed order into the table
    logging.info(f"Inserting the processed order with control number: {control_number}")
    control_number = str(control_number)
    try:
        entity = {
            "PartitionKey": "DispatchOrder",
            "RowKey": control_number,
            "OrderStatus": "Processed"
        }
        table_client.create_entity(entity)
        logging.info(f"Order with control number: {control_number} inserted into the table")
    except Exception as e:
        logging.error(f"Failed to insert the order into the table: {e}")
        logging.error(f"Entity details: {entity}")
        return func.HttpResponse(
            "Failed to insert the order into the table", status_code=500)
    
def save_failed_upload_to_table(table_client, control_number, file_content):
    # Save failed file upload details to Azure Table Storage
    logging.info(f"Saving failed upload details for ControlNumber={control_number} to Azure Table Storage")
    try:
        entity = {
            "PartitionKey": "FailedUploads",
            "RowKey": control_number,
            "FileContent": file_content,
            "Timestamp": datetime.datetime.utcnow().isoformat(),
        }
        table_client.create_entity(entity)
        logging.info(f"Failed upload saved: ControlNumber={control_number}")
    except Exception as e:
        logging.error(f"Failed to save file to Azure Table Storage: {e}")

def retry_failed_uploads(table_client, sftp_client):
    logging.info("Retrying failed SFTP uploads")
    try:
        failed_entities = table_client.query_entities("PartitionKey eq 'FailedUploads'")
        
        for entity in failed_entities:
            control_number = entity["RowKey"]
            file_content = entity["FileContent"]

            # Save content to a temporary file
            temp_file_path = f"{control_number}_retry.csv"
            with open(temp_file_path, "w") as file:
                file.write(file_content)

            # Retry SFTP upload
            try:
                sftp_client.put(temp_file_path, f"{sftp_incoming_folder}/{control_number}.csv")
                logging.info(f"Retry successful for ControlNumber={control_number}")

                # Remove entity from table after successful upload
                table_client.delete_entity("FailedUploads", control_number)
                logging.info(f"Removed ControlNumber={control_number} from Azure Table Storage")
            except Exception as e:
                logging.error(f"Retry failed for ControlNumber={control_number}: {e}")
            finally:
                os.remove(temp_file_path)
    except Exception as e:
        logging.error(f"Error during retry process: {e}")