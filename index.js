const { Aes, AesUtils } =require('@m92/crypto');

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types, @typescript-eslint/no-explicit-any
function encryptPayload(payload, tokenValue) {
  if (!tokenValue) {
    return payload;
  }
  const encryptionKey = AesUtils.extractKeyFromToken(tokenValue);
  const bodyString =
    typeof payload !== "string" ? JSON.stringify(payload) : payload;
  const encryptParams = {
    key: encryptionKey,
    data: bodyString,
  };
  const encryptedDataObj = Aes.encrypt("aes-256-gcm", encryptParams);
  const { payload: encryptedData } = encryptedDataObj;
  return encryptedData;
}

function decryptPayload(
  encryptedPayload,
  tokenValue
) {
  if (!tokenValue) {
    return encryptedPayload;
  }
  const decryptionKey = AesUtils.extractKeyFromToken(tokenValue);
  const decryptParams = { key: decryptionKey, payload: encryptedPayload };
  const decryptedDataObj = Aes.decrypt("aes-256-gcm", decryptParams);
  
  const { data: decryptedDataString } = decryptedDataObj;
  const decryptedData = JSON.parse(decryptedDataString);
  return decryptedData;
}

module.exports = {encryptPayload,decryptPayload}