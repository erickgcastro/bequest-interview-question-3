import React, { useEffect, useState } from "react"

const API_URL = "http://localhost:8080"

function App() {
  const [data, setData] = useState<string>("")
  const [signature, setSignature] = useState<string>("")
  const [publicKey, setPublicKey] = useState<CryptoKey>()

  useEffect(() => {
    getData()
    fetchPublicKey()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /**
   * Function to fetch data and signature from the API.
   * It updates the 'data' and 'signature' states with the response from the API.
   */
  const getData = async () => {
    const response = await fetch(API_URL)
    const { data, signature } = await response.json()
    setData(data)
    setSignature(signature)
  }

  /**
   * Function to fetch the public key in PEM format from the API.
   * It converts the PEM public key into a CryptoKey object and stores it in the 'publicKey' state.
   */
  const fetchPublicKey = async () => {
    const response = await fetch(`${API_URL}/public-key`)
    const publicKeyPem = await response.text()

    // Convert the PEM public key to CryptoKey using the Web Crypto API
    const importedKey = await window.crypto.subtle.importKey(
      "spki",
      pemToArrayBuffer(publicKeyPem),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["verify"]
    )
    setPublicKey(importedKey)
  }

  /**
   * Function to update the data and signature on the API.
   * First, the function makes a request to sign the data, then sends the data and signature to the server.
   */
  const updateData = async () => {
    const signResponse = await fetch(`${API_URL}/sign`, {
      method: "POST",
      body: JSON.stringify({ data }),
      headers: { "Content-Type": "application/json" },
    })
    const { signature } = await signResponse.json()

    const response = await fetch(`${API_URL}`, {
      method: "POST",
      body: JSON.stringify({ data, signature }),
      headers: { "Content-Type": "application/json" },
    })

    if (response.status >= 400) {
      alert("Invalid signature")
    } else {
      await getData()
    }
  }

  /**
   * Function to verify the integrity of the data using the public key.
   * It checks if the signature is valid for the data using the public key.
   */
  const verifyDataIntegrity = async () => {
    if (!publicKey || !signature) {
      alert("Public key or signature not available.")
      return
    }

    const encoder = new TextEncoder()
    const isValid = await window.crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      publicKey,
      Uint8Array.from(atob(signature), (c) => c.charCodeAt(0)),
      encoder.encode(data)
    )

    if (isValid) {
      alert("Data integrity verified!")
    } else {
      alert("Data has been tampered with!")
    }
  }

  /**
   * Function to convert the PEM public key to ArrayBuffer.
   * The PEM public key is converted into the required format for Web Crypto API.
   */
  const pemToArrayBuffer = (pem: string) => {
    const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "")
    const binary = atob(b64)
    const arrayBuffer = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      arrayBuffer[i] = binary.charCodeAt(i)
    }
    return arrayBuffer.buffer
  }

  return (
    <div
      style={{
        width: "100vw",
        height: "100vh",
        display: "flex",
        position: "absolute",
        padding: 0,
        justifyContent: "center",
        alignItems: "center",
        flexDirection: "column",
        gap: "20px",
        fontSize: "30px",
      }}
    >
      <div>Saved Data</div>
      <input
        style={{ fontSize: "30px" }}
        type="text"
        value={data}
        onChange={(e) => setData(e.target.value)}
      />

      <div style={{ display: "flex", gap: "10px" }}>
        <button style={{ fontSize: "20px" }} onClick={updateData}>
          Update Data
        </button>
        <button style={{ fontSize: "20px" }} onClick={verifyDataIntegrity}>
          Verify Data
        </button>
        <button
          style={{ fontSize: "20px" }}
          onClick={() => {
            setSignature("othersignature")
          }}
        >
          Tamper content
        </button>
        <button
          style={{ fontSize: "20px" }}
          onClick={() => {
            getData()
          }}
        >
          Recover Data
        </button>
      </div>
    </div>
  )
}

export default App
