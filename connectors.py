import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import pickle
import imaplib
import email
from email.header import decode_header
import datetime
import io
from typing import Dict, List, Optional, Union
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GoogleDriveConnector:
    """Handles connections and operations with Google Drive."""
    
    SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
    
    def __init__(self, credentials_path: str, token_path: str):
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.creds = None
        self.service = None
    
    def authenticate(self) -> None:
        """Authenticate with Google Drive."""
        try:
            if os.path.exists(self.token_path):
                with open(self.token_path, 'rb') as token:
                    self.creds = pickle.load(token)

            if not self.creds or not self.creds.valid:
                if self.creds and self.creds.expired and self.creds.refresh_token:
                    self.creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_path, self.SCOPES)
                    self.creds = flow.run_local_server(port=0)
                
                with open(self.token_path, 'wb') as token:
                    pickle.dump(self.creds, token)

            self.service = build('drive', 'v3', credentials=self.creds)
            logger.info("Successfully authenticated with Google Drive")
            
        except Exception as e:
            logger.error(f"Error authenticating with Google Drive: {str(e)}")
            raise

    def list_files(self, folder_id: Optional[str] = None, file_types: Optional[List[str]] = None) -> List[Dict]:
        """
        List files in Google Drive, optionally filtered by folder and file types.
        
        Args:
            folder_id: Optional ID of the folder to list files from
            file_types: Optional list of file MIME types to filter by
        
        Returns:
            List of dictionaries containing file information
        """
        try:
            query = []
            if folder_id:
                query.append(f"'{folder_id}' in parents")
            if file_types:
                mime_types = [f"mimeType='{type}'" for type in file_types]
                query.append(f"({' or '.join(mime_types)})")
            
            query_string = ' and '.join(query) if query else None
            
            results = self.service.files().list(
                q=query_string,
                pageSize=1000,
                fields="files(id, name, mimeType, createdTime, modifiedTime)"
            ).execute()
            
            return results.get('files', [])
            
        except Exception as e:
            logger.error(f"Error listing files from Google Drive: {str(e)}")
            raise

    def download_file(self, file_id: str, output_path: str) -> bool:
        """
        Download a file from Google Drive.
        
        Args:
            file_id: ID of the file to download
            output_path: Path where the file should be saved
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            request = self.service.files().get_media(fileId=file_id)
            file = io.BytesIO()
            downloader = MediaIoBaseDownload(file, request)
            done = False
            
            while done is False:
                status, done = downloader.next_chunk()
                if status:
                    logger.info(f"Download Progress: {int(status.progress() * 100)}%")
            
            file.seek(0)
            with open(output_path, 'wb') as f:
                f.write(file.read())
                
            return True
            
        except Exception as e:
            logger.error(f"Error downloading file from Google Drive: {str(e)}")
            return False


class EmailConnector:
    """Handles connections and operations with email servers."""
    
    def __init__(self, email_address: str, password: str, imap_server: str = "imap.gmail.com"):
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.connection = None

    def connect(self) -> bool:
        """
        Establish connection to the email server.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.connection = imaplib.IMAP4_SSL(self.imap_server)
            self.connection.login(self.email_address, self.password)
            logger.info("Successfully connected to email server")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to email server: {str(e)}")
            return False

    def disconnect(self) -> None:
        """Close the email server connection."""
        if self.connection:
            try:
                self.connection.logout()
                logger.info("Successfully disconnected from email server")
            except Exception as e:
                logger.error(f"Error disconnecting from email server: {str(e)}")

    def fetch_emails(self, 
                    folder: str = "INBOX", 
                    days: int = 7, 
                    sender: Optional[str] = None,
                    subject_contains: Optional[str] = None) -> List[Dict]:
        """
        Fetch emails based on specified criteria.
        
        Args:
            folder: Email folder to search in
            days: Number of days to look back
            sender: Optional sender email address to filter by
            subject_contains: Optional subject text to filter by
        
        Returns:
            List of dictionaries containing email information
        """
        try:
            self.connection.select(folder)
            date_since = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%d-%b-%Y")
            
            search_criteria = [f'SINCE "{date_since}"']
            if sender:
                search_criteria.append(f'FROM "{sender}"')
            
            _, message_numbers = self.connection.search(None, *search_criteria)
            
            emails = []
            for num in message_numbers[0].split():
                _, msg_data = self.connection.fetch(num, '(RFC822)')
                email_body = msg_data[0][1]
                message = email.message_from_bytes(email_body)
                
                subject = decode_header(message["subject"])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()
                
                if subject_contains and subject_contains.lower() not in subject.lower():
                    continue
                
                from_ = decode_header(message["from"])[0][0]
                if isinstance(from_, bytes):
                    from_ = from_.decode()
                
                date = email.utils.parsedate_to_datetime(message["date"])
                
                # Extract body
                body = ""
                if message.is_multipart():
                    for part in message.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            break
                else:
                    body = message.get_payload(decode=True).decode()
                
                emails.append({
                    "subject": subject,
                    "from": from_,
                    "date": date.isoformat(),
                    "body": body
                })
            
            return emails
            
        except Exception as e:
            logger.error(f"Error fetching emails: {str(e)}")
            raise

    def save_attachments(self, 
                        email_id: str, 
                        output_dir: str, 
                        file_types: Optional[List[str]] = None) -> List[str]:
        """
        Save attachments from a specific email.
        
        Args:
            email_id: ID of the email
            output_dir: Directory to save attachments
            file_types: Optional list of file extensions to filter by
        
        Returns:
            List of saved file paths
        """
        try:
            _, msg_data = self.connection.fetch(email_id, '(RFC822)')
            email_body = msg_data[0][1]
            message = email.message_from_bytes(email_body)
            
            saved_files = []
            
            for part in message.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                
                filename = part.get_filename()
                if not filename:
                    continue
                
                if file_types and not any(filename.lower().endswith(ft.lower()) for ft in file_types):
                    continue
                
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(part.get_payload(decode=True))
                saved_files.append(filepath)
            
            return saved_files
            
        except Exception as e:
            logger.error(f"Error saving attachments: {str(e)}")
            raise 