#!/usr/bin/env node
const M92 =require("./node_modules/@m92/crypto/dist");

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any
function encryptPayload(payload, tokenValue) {
  if (!tokenValue) {
    return payload;
  }
  const encryptionKey = M92.AesUtils.extractKeyFromToken(tokenValue);
  const bodyString =
    typeof payload !== "string" ? JSON.stringify(payload) : payload;
  const encryptParams = {
    key: encryptionKey,
    data: bodyString,
  };
  const encryptedDataObj = M92.Aes.encrypt("aes-256-gcm", encryptParams);
  const { payload: encryptedData } = encryptedDataObj;
  return encryptedData;
}

function decryptPayload(encryptedPayload, tokenValue) {
  if (!tokenValue) {
    return encryptedPayload;
  }
  const decryptionKey = M92.AesUtils.extractKeyFromToken(tokenValue);
  const decryptParams = { key: decryptionKey, payload: encryptedPayload };
  const decryptedDataObj = M92.Aes.decrypt("aes-256-gcm", decryptParams);

  const { data: decryptedDataString } = decryptedDataObj;
  const decryptedData = JSON.parse(decryptedDataString);
  return decryptedData;
}

module.exports = { encryptPayload, decryptPayload }