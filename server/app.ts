import crypto from "crypto"
import express from "express"
import cors from "cors"
import morgan from "morgan"

const PORT = 8080
const app = express()
const database = { data: "Hello World" }

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
})

// Convert public key to PEM format
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString()

app.use(morgan("dev"))
app.use(cors())
app.use(express.json())

// Endpoints

/**
 * GET endpoint to retrieve the stored data and its associated signature.
 * This endpoint signs the current data from the 'database' object and returns it along with the signature.
 */
app.get("/", (req, res) => {
  const signature = crypto
    .sign("sha256", Buffer.from(database.data), privateKey)
    .toString("base64")
  res.json({ data: database.data, signature })
})

/**
 * POST endpoint to update the data if the signature is valid.
 * The signature is verified using the public key.
 * If the signature is valid, the data is updated in the 'database' object.
 */
app.post("/", (req, res) => {
  const { data, signature } = req.body

  const isValid = crypto.verify(
    "sha256",
    Buffer.from(data),
    publicKey,
    Buffer.from(signature, "base64")
  )

  if (isValid) {
    database.data = data
    res.sendStatus(200)
  } else {
    res.status(400).json({ error: "Invalid signature" })
  }
})

/**
 * GET endpoint to fetch the public key in PEM format.
 * This allows clients to retrieve the public key to verify signatures.
 */
app.get("/public-key", (req, res) => {
  res.type("text/plain").send(publicKeyPem)
})

/**
 * POST endpoint to generate and return a signature for the provided data.
 * This endpoint signs the data using the server's private key and returns the signature.
 */
app.post("/sign", (req, res) => {
  const { data } = req.body
  const signature = crypto
    .sign("sha256", Buffer.from(data), privateKey)
    .toString("base64")
  res.json({ signature })
})

app.listen(PORT, () => {
  console.log("Server running on port " + PORT)
})
