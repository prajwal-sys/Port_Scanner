import unittest
from unittest.mock import patch, MagicMock, call
import socket
import mysql.connector
import sys
import os
import io
from contextlib import redirect_stdout

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import PortScanner

class TestPortScanner(unittest.TestCase):
    
    def setUp(self):
        self.test_target = "127.0.0.1"
        self.test_start_port = 80
        self.test_end_port = 85
        self.test_user_id = 1
        
        self.mock_db = MagicMock()
        self.mock_cursor = MagicMock()
        self.mock_db.cursor.return_value = self.mock_cursor
        
    @patch('socket.socket')
    @patch('socket.getservbyport')
    @patch('socket.gethostbyaddr')
    def test_port_scanner_initialization(self, mock_gethostbyaddr, mock_getservbyport, mock_socket):
        mock_gethostbyaddr.return_value = ["localhost", [], []]
        
        scanner = PortScanner.PortScanner(
            self.test_target, 
            self.test_start_port, 
            self.test_end_port, 
            user_id=self.test_user_id
        )
        
        self.assertEqual(scanner.target, self.test_target)
        self.assertEqual(scanner.start_port, self.test_start_port)
        self.assertEqual(scanner.end_port, self.test_end_port)
        self.assertEqual(scanner.user_id, self.test_user_id)
        self.assertEqual(scanner.hostname, "localhost")
        self.assertEqual(scanner.open_ports, [])
        
        mock_gethostbyaddr.assert_called_once_with(self.test_target)
    
    @patch('socket.socket')
    @patch('socket.getservbyport')
    def test_scan_port_open(self, mock_getservbyport, mock_socket):

        mock_socket_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_socket_instance
        mock_socket_instance.connect_ex.return_value = 0
        mock_getservbyport.return_value = "http"
        
        scanner = PortScanner.PortScanner(
            self.test_target, 
            self.test_start_port, 
            self.test_end_port, 
            user_id=self.test_user_id
        )
        
        captured_output = io.StringIO()
        with redirect_stdout(captured_output):
            scanner.scan_port(80)
        
        self.assertEqual(scanner.open_ports, [(80, "http")])
        
        mock_getservbyport.assert_called_once_with(80, 'tcp')
        
        self.assertIn("Port 80 (http) is open", captured_output.getvalue())
    
    @patch('socket.socket')
    @patch('socket.getservbyport')
    def test_scan_port_closed(self, mock_getservbyport, mock_socket):
        mock_socket_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_socket_instance
        mock_socket_instance.connect_ex.return_value = 1
        
        scanner = PortScanner.PortScanner(
            self.test_target, 
            self.test_start_port, 
            self.test_end_port, 
            user_id=self.test_user_id
        )
        
        scanner.scan_port(80)
        
        self.assertEqual(scanner.open_ports, [])
        
        mock_getservbyport.assert_not_called()
    
    @patch('PortScanner.connect_db')
    @patch('PortScanner.ThreadPoolExecutor')
    @patch('socket.gethostbyaddr')
    def test_run_scan(self, mock_gethostbyaddr, mock_executor, mock_connect_db):
        # Set up mocks
        mock_gethostbyaddr.return_value = ["localhost", [], []]
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_db.cursor.return_value = mock_cursor
        mock_connect_db.return_value = mock_db
        
        scanner = PortScanner.PortScanner(
            self.test_target, 
            self.test_start_port, 
            self.test_end_port, 
            user_id=self.test_user_id
        )
        
        scanner.open_ports = [(80, "http"), (443, "https")]
        
        captured_output = io.StringIO()
        with redirect_stdout(captured_output):
            scanner.run_scan()
        
        mock_executor.assert_called_once_with(max_workers=100)
        
        mock_executor_instance.map.assert_called_once()
        
        mock_connect_db.assert_called_once()
        self.assertEqual(mock_cursor.execute.call_count, 1 + len(scanner.open_ports))
        
        self.assertIn("Scanning target: 127.0.0.1", captured_output.getvalue())
        self.assertIn("Scan completed in", captured_output.getvalue())
        self.assertIn("Scan results saved to history", captured_output.getvalue())

    @patch('mysql.connector.connect')
    def test_database_connection(self, mock_connect):
        mock_db = MagicMock()
        mock_connect.return_value = mock_db
        
        result = PortScanner.connect_db()
        
        mock_connect.assert_called_once_with(
            host="localhost",
            user="root",
            password="",
            database="port_scanner"
        )
        
        self.assertEqual(result, mock_db)
    
    @patch('mysql.connector.connect')
    def test_create_tables(self, mock_connect):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_db.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_db
        
        PortScanner.create_tables()
        
        self.assertEqual(mock_cursor.execute.call_count, 2)
        
        for call_args in mock_cursor.execute.call_args_list:
            self.assertIn("CREATE TABLE IF NOT EXISTS", call_args[0][0])
        
        mock_db.commit.assert_called_once()
        mock_cursor.close.assert_called_once()
        mock_db.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()