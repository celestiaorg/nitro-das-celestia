{
  "chainId": "celestia",
  "chainName": "Celestia",
  "status": "live",
  "networkType": "mainnet",
  "bech32Prefix": "celestia",
  "coinType": 118,
  "active": true,
  
  // High-Availability Infrastructure
  // Note: Using multiple providers is recommended for production resilience
  "node": {
    "rpc": "https://public-celestia-rpc.numia.xyz",
    "rest": "https://public-celestia-lcd.numia.xyz",
    "grpc": "https://public-celestia-grpc.numia.xyz"
  },

  // Verification & Audit Tools
  "explorers": {
    "celenium": {
      "name": "Celenium (Best for Blobs)",
      "url": "https://celenium.io/",
      "txUrl": "https://celenium.io/tx/"
    },
    "mintscan": {
      "name": "Mintscan (Best for Governance)",
      "url": "https://www.mintscan.io/celestia/",
      "txUrl": "https://www.mintscan.io/celestia/tx/"
    }
  },

  // Token Metrics & Display
  "currencies": [
    {
      "displayDenom": "TIA",
      "baseDenom": "utia",
      "decimals": 6,
      "coinGeckoId": "celestia",
      "logo": "/logos/celestia-logo-purple.svg"
    }
  ],

  // Inter-Blockchain Communication (IBC) Logic
  // Facilitates trustless data transfer between modular layers
  "ibc": {
    "timeout": 600000,
    "sourceChannel": "channel-27",
    "destinationChannel": "channel-4",
    "allowedDenoms": ["utia"]
  },

  // Dynamic Gas Pricing Strategy
  "gasPriceSteps": {
    "low": 0.01,
    "average": 0.02,
    "high": 0.1
  },

  "metadata": {
    "website": "https://celestia.org/",
    "logo": "/logos/celestia-logo-purple.svg",
    "description": "Modular Data Availability Network for the Multichain Future."
  }
}
