# MyMacca's Offers Fetcher [Console Application]

## Description

A simple console application automating the process of fetching MyMacca's offers for multiple accounts. It uses the Gmail API to handle magic link authentication and interacts with the MyMacca's API to retrieve the latest offers.

## Features

-   Automatic login using magic links sent to Gmail inbox
-   Fetches offers for multiple McDonald's accounts
-   Displays offers and loyalty points in an easy-to-read format

## Prerequisites

-   .NET 8.0 or later
-   Google Cloud Console project with Gmail API enabled
-   `client_secret.json` file for Gmail API authentication

## Setup

1. Clone this repository
2. Place your `client_secret.json` file in the project root directory
3. Create a `config.json` file based on `config.template.json` and fill in your details
4. Build the project using `dotnet build` or through Visual Studio

## Usage

Run the application using: `dotnet run` or run it through Visual Studio.

The application will process each account sequentially and output the results to both the console and a log file.

## Configuration

Edit the `config.json` file to set up your accounts and API details. Ensure all required fields are filled out correctly.
