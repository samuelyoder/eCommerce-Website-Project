# eCommerce Simulator

## Overview
The eCommerce Simulator is a web application built with Flask, SQLite3, and HTML, designed to manage an online store with products, customers, vendors, and a personalized tiered discount/rewards system. It supports user authentication (admin and customer roles), CRUD operations for products, customers, vendors, and discounts, and a dynamic discount system that assigns 15%, 10%, and 5% discounts based on customer purchase history. The database is initialized from and synchronized with a `sample_data.txt` file, ensuring data persistence.

## Features
- **User Authentication**: Login for admins and customers, public registration for customers, passwords stored as salted hashes.
- **Shopping Interface**: Customers can view and purchase products with applicable discounts.
- **Admin Management**: CRUD operations for products, customers, vendors, and discounts.
- **Tiered Discount System**: Automatically assigns discounts (15%, 10%, 5%) to customers based on total purchases (5, 10, 20) and category-specific purchase counts (5+ per category).
- **Recommendations**: Admins can generate product recommendations and manually assign discounts.
- **Data Synchronization**: Database state is synced with `sample_data.txt` for persistence.

## Technologies
- **Backend**: Flask (Python), SQLite3
- **Frontend**: HTML with minimal CSS
- **Data Storage**: SQLite database (`database.db`) and `sample_data.txt`

## Installation
### Prerequisites
- Python 3.9+
- Flask (`pip install flask`)
- SQLite3 (included with Python)

### Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/samuelyoder/eCommerce-Website-Project.git
   cd eCommerce-Website-Project
   ```

2. **Install Dependencies**:
   ```bash
   pip install flask
   ```

3. **The Data File**:
   - `sample_data.txt` in the project root holds the seed data (102 products, 51 customers, 26 vendors, plus purchases, supply links and discounts). The database is rebuilt from it at every start and written back to it after every change.
   - Products, customers and vendors are stored with their IDs so purchases and discounts keep pointing at the same records across restarts. Users are stored with a password hash, never the password. The shipped file has no user accounts.
     ```
     PRODUCTS
     1,399.99,Laptop,Electronics
     CUSTOMERS
     1,Alice
     VENDORS
     1,TechTrendz
     BUYS
     1,1,0
     USERS
     alice,scrypt:32768:8:1$<salt>$<hash>,Customer,1
     ```

4. **Run the Application**:
   No admin account ships with the app. Choose a password when you start it and an `admin` account is created with it:
   ```bash
   # macOS / Linux / WSL
   ADMIN_PASSWORD='choose-a-password' python app.py
   ```
   ```powershell
   # Windows PowerShell
   $env:ADMIN_PASSWORD = "choose-a-password"
   python app.py
   ```
   - The app runs at `http://localhost:5000`.
   - Optional environment variables: `ADMIN_USERNAME` (default `admin`), `SECRET_KEY` (signs session cookies; if unset, a random key is generated at each start, which logs everyone out on restart) and `FLASK_DEBUG=1` (debug mode, off by default; never enable it on a reachable host).
   - Running the app rewrites `sample_data.txt`, including the hashes of any accounts you create. Restore the original with `git checkout sample_data.txt` before committing.

## Database Schema
The SQLite database (`database.db`) includes seven tables:

1. **Product** (`PID`, `Price`, `Name`, `Category`)
   - Primary Key: `PID`
   - Example: `(1, 999.99, 'Laptop', 'Electronics')`

2. **Customer** (`CID`, `Name`)
   - Primary Key: `CID`
   - Example: `(1, 'Jane Doe')`

3. **Vendor** (`VID`, `Name`)
   - Primary Key: `VID`
   - Example: `(1, 'TechCorp')`

4. **Discount** (`DID`, `Percentage`, `Type`, `CID`, `Category`)
   - Primary Key: `DID`
   - Foreign Key: `CID → Customer(CID)`
   - Example: `(1, 15.0, 'Rewards', 1, 'Electronics')`

5. **Buys** (`CID`, `PID`, `DiscountApplied`)
   - Primary Key: `(CID, PID)`
   - Foreign Keys: `CID → Customer(CID)`, `PID → Product(PID)`
   - Example: `(1, 1, 1)`

6. **Supplies** (`VID`, `PID`)
   - Primary Key: `(VID, PID)`
   - Foreign Keys: `VID → Vendor(VID)`, `PID → Product(PID)`
   - Example: `(1, 1)`

7. **Users** (`UID`, `Username`, `Password`, `UserType`, `CID`)
   - Primary Key: `UID`
   - Foreign Key: `CID → Customer(CID)`
   - `Password` holds a salted scrypt hash from `werkzeug.security`, not the password itself
   - Example: `(1, 'admin', 'scrypt:32768:8:1$...', 'Admin', NULL)`

## Usage
### Running the App
1. Start the server with an admin password (see Run the Application above).
2. Open `http://localhost:5000` in a browser.

### Example Scenarios
1. **Admin Actions**:
   - **Login**: Use `admin` and the `ADMIN_PASSWORD` you started the app with.
   - **Manage Products**: Go to `/products` to add (e.g., `Mouse`, $99.99, Electronics), update, or delete products.
   - **View Customers**: Go to `/customers` to add/delete customers or view a customer's purchase history.
   - **Manage Discounts**: Go to `/discounts` to generate recommendations for a customer (e.g., Electronics products) or manually assign a 10% Clothing discount.

2. **Customer Actions**:
   - **Register and log in**: Create an account on the login page with a username, password and full name. Each registration creates a new customer record.
   - **Shop**: Go to `/shop` to view unpurchased products. Purchase a product to trigger discount updates (e.g., after 5 Electronics purchases, the remaining Electronics products show 15% off).
   - **Discounts**: After 5 Electronics purchases, see a 15% discount; after 10 total (including 5 Clothing), see a 10% Clothing discount.

### Key Routes
- `/`: Login and registration page.
- `/shop`: Customer shopping interface with discounted products.
- `/products`: Admin product management (CRUD).
- `/customers`: Admin customer management and purchase history.
- `/vendors`: Admin vendor management with performance analysis.
- `/discounts`: Admin discount management and recommendations.
- `/logout`: Clears session and returns to login.

## Tiered Discount System
The advanced feature is a personalized discount system:
- **Logic**: Assigns discounts based on total purchases and category-specific counts:
  - 15% off the most-purchased category (5+ purchases, 5 total purchases).
  - 10% off the second most-purchased (5+ purchases, 10 total).
  - 5% off the third most-purchased (5+ purchases, 20 total).
- **Implementation**: The `update_discounts` function in `app.py` uses `GROUP BY` to rank categories and `DELETE`/`INSERT` to update discounts.
- **Example**: A customer with 5 Electronics, 5 Clothing, 3 Books purchases gets 15% off Electronics and 10% off Clothing after 10 total purchases.
- **Uniqueness**: Unlike static coupon systems, discounts are dynamic, category-specific, and automatically updated after purchases.

## Security
The app went through a security review. Each problem found and its fix:

| Problem | Fix |
|---|---|
| Public registration offered an Admin account type, so anyone could become an admin | Registration only creates Customer accounts. The admin account comes from the `ADMIN_PASSWORD` environment variable |
| Session cookies were signed with a hardcoded key published in the source, so an admin session could be forged without an account | The key comes from `SECRET_KEY` or is generated randomly at startup |
| Passwords were stored in plain text in the database and in `sample_data.txt`, and the seed accounts were committed | Passwords are hashed with `werkzeug.security` (scrypt, salted). The seed accounts and the committed `database.db` were removed |
| No CSRF protection: another site could make a logged-in admin delete or change records | Every form carries a per-session token that is checked on each POST. Session cookies are `SameSite=Lax` |
| A name containing line breaks was written to `sample_data.txt` as extra records, which could add an Admin account at the next restart | Usernames and other text fields are rejected if they contain commas, `#` or line breaks |
| Registering with an existing customer's name linked the new account to that customer's purchases and discounts | Every registration creates its own customer record |
| After a restart, IDs were reassigned by line order, so deleting a customer could move purchases and discounts to other customers | IDs are saved in `sample_data.txt`, and deleting a product, customer or vendor also deletes the rows that point to it |
| Malformed input (a blank name, a non-numeric price) caused 500 errors | Required fields are checked and malformed numbers return 400 |
| Flask debug mode was always on, exposing the interactive debugger | Debug mode is off unless `FLASK_DEBUG=1` is set |

Database queries are parameterized and Jinja2 escapes all template output, so user input is never run as SQL or rendered as HTML.

## Testing
The tests in `tests/test_security.py` cover each fix above, plus a check that purchases still unlock the rewards discount. They run against a temporary copy of `sample_data.txt`, so the repository's files are not changed.

```bash
pip install flask
python -m unittest discover -s tests -v
```
