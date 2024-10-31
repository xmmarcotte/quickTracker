
# Granite QuickTracker

Granite QuickTracker is a Python application that allows users to track shipments and query ticket information from a database using customtkinter for the GUI interface.

## Features

- GUI-based application for quick user input and display.
- Shipment tracking for UPS, FedEx, and USPS.
- Database query functionality for Granite Telecommunications' systems.

## Prerequisites

- **Python 3.x**: Make sure Python is installed on your machine.
- **Virtual Environment**: (Optional but recommended) Use a virtual environment to manage dependencies.

## Installation

1. **Clone the repository** (if not already done):
   ```bash
   git clone <repository-url>
   cd Granite-QuickTracker
   ```

2. **Set up a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install required packages**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Create a `.env` file** in the root directory of the project to store sensitive API tokens:

   ```plaintext
   UPS_AUTH="bVVJaEV6OElobHY3OHAyRDlaQ01HQjNaRUpXRzN3MVFOdVNPWVNGVVloMDZNMHI4OklJVlVnYW1xZzltb3psMGx0RUhJb2Y1eGd6SE5XeVhCOHlOdHR4N2ZBb3BSenh6eWNWQzlNOVFCOUpkc3BqeDk="
   FEDEX_CLIENT_ID="l7a26c4d47bf0e4973b6a5ce551e9a8d90"
   FEDEX_CLIENT_SECRET="a288c01b540944168327bd345099cd99"
   ```

## Usage

1. **Run the application**:
   ```bash
   python quicktracker.py
   ```

2. **Enter credentials**:
   - Enter your database credentials in the GUI upon prompt.
   
3. **Track tickets**:
   - Enter ticket numbers separated by commas, spaces, or line breaks.
   - The application will display the tracking status and estimated delivery information.

## Environment Variables

The application requires sensitive information to be stored in environment variables. Ensure that the following variables are set in a `.env` file in the project root:

```plaintext
UPS_AUTH="your_ups_auth_token"
FEDEX_CLIENT_ID="your_fedex_client_id"
FEDEX_CLIENT_SECRET="your_fedex_client_secret"
```

## License

This project is for internal use by Granite Telecommunications and should not be distributed outside the company.

---
