
import streamlit as st
import hashlib
import requests
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error
import matplotlib.pyplot as plt
import yfinance as yf  # Using yfinance for convenient data retrieval

# Function to securely hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = None
if 'user_data' not in st.session_state:
    st.session_state['user_data'] = {}

# Registration function
def register():
    st.subheader("Register")
    username = st.text_input("Username", key="register_username")
    email = st.text_input("Email", key="register_email")
    password = st.text_input("Password", type="password", key="register_password")
    confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm_password")

    if st.button("Register"):
        if not username or not email or not password:
            st.warning("Please fill in all fields.")
        elif username in st.session_state['user_data']:
            st.warning("Username already exists!")
        elif password != confirm_password:
            st.warning("Passwords do not match!")
        else:
            st.session_state['user_data'][username] = {
                "email": email,
                "password": hash_password(password),
            }
            st.success("Registration successful! You can now log in.")

# Login function
def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        user_data = st.session_state['user_data']
        hashed_password = hash_password(password)
        if username in user_data and user_data[username]['password'] == hashed_password:
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid username or password.")

# User details function
def user_details():
    username = st.session_state['username']
    if username:
        st.subheader("User Details")
        st.write(f"Username: {username}")
        st.write(f"Email: {st.session_state['user_data'][username]['email']}")

# Logout function
def logout():
    st.session_state['logged_in'] = False
    st.session_state['username'] = None
    st.info("You have logged out.")

# Function to fetch market data from Alpha Vantage (replace with your API key)
def fetch_market_data():
    st.subheader("Market Data")

    api_key = "XGGBQFHKV1HUKK4K"  # Replace with your actual Alpha Vantage API key
    base_url = "https://www.alphavantage.co/query"

    symbol = st.text_input("Enter stock symbol (e.g., AAPL)", value="AAPL")
    if st.button("Fetch Data"):
        params = {
            "function": "TIME_SERIES_DAILY",
            "symbol": symbol,
            "outputsize": "compact",
            "apikey": api_key
        }
        try:
            response = requests.get(base_url, params=params)
            response.raise_for_status()

            data = response.json()
            if "Error Message" in data:
                st.error("Error with API key or symbol. Please check your inputs.")
                return None

            time_series = data.get("Time Series (Daily)", {})
            if not time_series:
                st.error("Failed to fetch data. Check your API key or symbol.")
                return None

            # Convert data to DataFrame
            df = pd.DataFrame.from_dict(time_series, orient="index")
            df = df.rename(columns={
                "1. open": "Open",
                "2. high": "High",
                "3. low": "Low",
                "4. close": "Close",
                "5. volume": "Volume"
            })
            df.index = pd.to_datetime(df.index)
            df = df.sort_index()

            st.write("### Daily Stock Prices")
            st.dataframe(df.head(20))

            # Plot the closing prices
            st.line_chart(df["Close"])

            return df

        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching data: {e}")
            return None