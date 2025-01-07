import azure.functions as func
import logging
import json
import os
import csv
from jsonschema import validate, ValidationError
from models.json_model import ReadyForDispatch
from models.cvs_model import CsvModel


MAX_PAYLOAD_SIZE_KB = 800

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
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

        #map the json data to csv
        mapped_csv_data = map_json_to_csv(dispatch_data)
        logging.info("Dispatch data mapped to CSV.")
        logging.info(f"CSV data: {mapped_csv_data}")

        #write to csv file
        output_file = "dispatch_data.csv"
        write_to_csv_file(mapped_csv_data, output_file)
        logging.info(f"Dispatch data written to CSV file {output_file}")

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
                containerType=container.containerType,
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


def connect_to_SFTP():
    # Connect to the SFTP server
    logging.info("Connecting to SFTP server")
    

def upload_to_SFTP():
    # Upload the CSV file to the SFTP server
    logging.info("Uploading the CSV file to SFTP server")