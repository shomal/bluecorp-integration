import logging
from azure.data.tables import TableServiceClient
import azure.functions as func
from function_app import retry_failed_uploads, connect_to_SFTP
import os

table_connection_string = os.getenv("AzureWebJobsStorage")
table_name = os.getenv("AZURE_TABLE_NAME")

@app.function_name(name="retry_failed_uploads")
@app.schedule(schedule="0 */15 * * * *", arg_name="mytimer", run_on_startup=False, use_monitor=True)
def retry_timer_function(mytimer: func.TimerRequest) -> None:
    logging.info("Retry timer triggered")

    table_service_client = TableServiceClient.from_connection_string(table_connection_string)
    table_client = table_service_client.get_table_client(table_name)

    with open("bluecorp_rsa_id", "r") as key_file:
        private_key = key_file.read()

    sftp_client = connect_to_SFTP(private_key)

    retry_failed_uploads(table_client, sftp_client)


