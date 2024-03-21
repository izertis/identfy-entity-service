import Joi from "joi";

export default class CredentialSchema {
  credentialRequest = {
    body: Joi.object({
      types: Joi.array()
        .items(Joi.string())
        .description("Credential types requested")
        .example(["VerifiableCredential", "VerifiableAttestation", "CTWalletSameInTime"]),
      format: Joi.string()
        .valid("jwt_vc")
        .description("Format of the returned credentials")
        .example("jwt_vc"),
      proof: Joi.object({
        proof_type: Joi.string().valid("jwt").required().label("PROOF_TYPE").example("jwt"),
        jwt: Joi.string()
          .min(20)
          .regex(/^ey/)
          .required()
          .label("JWT")
          .example(
            "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzRVl2ZHJqeE1qUTR0cG5qZTlCREJUenVORFAza25uNnFMWkVyemQ0Yko1Z28yQ0Nob1BqZDVH(...)DNrbm42cUxaRXJ6ZDRiSjVnbzJDQ2hvUGpkNUdBSDN6cEZKUDVmdXdTazY2VTVQcTZFaEY0bktuSHpEbnpuRVA4Zlg5OW5aR2d3YkFoMW83R2oxWDUyVGRoZjdVNEtUazY2eHNBNXIiLCJhdWQiOiJodHRwczovL215LWlzc3Vlci5yb2Nrcy9hdXRoIiwiZXhwIjoxNTg5Njk5OTYyLCJub25jZSI6IlBBUFBmM2g5bGV4VHYzV1lIWng4YWpUZSJ9.1AK6J-nxkNvQiRehrP7Z3GmXEn-1I7na1ttIMr5cX_nfKSiMCN2-RxY01zAnB-JQ-l5sZEmzWiuvKgRzCD7fUA"
          ),
      }).description("Proof object containing proof_type and jwt"),
      issuerDid: Joi.string()
        .description("The issuer DID")
        .example("did:ebsi:zvHWX359A3CvfJnCYaAiAde"),
      issuerUri: Joi.string()
        .description("The issuer URI")
        .example("https://my.example.issuer/issuer"),
      privateKeyJwk: privateKeyJwk
        .description("Private Keys in JSON Web Key (JWK) to sign the VC")
        .example({
          kty: "EC",
          x: "ujcuaJoOpnBxYYtlipyFQIahB5GDafNWO1TE2MR7YUI",
          y: "QOSoMUrerJI_kk5X34ACrmLB9adRstwmCWtdGYa_QKg",
          crv: "P-256",
          d: "V2Mgya-Tq13ltrW2JDRDNG3O0rOH6h59bhyARnDTpmQ",
        }),
      publicKeyJwk: publicKeyJwk.description("Public Key in JSON Web Key (JWK)").example({
        kty: "EC",
        x: "ujcuaJoOpnBxYYtlipyFQIahB5GDafNWO1TE2MR7YUI",
        y: "QOSoMUrerJI_kk5X34ACrmLB9adRstwmCWtdGYa_QKg",
        crv: "P-256",
        d: "V2Mgya-Tq13ltrW2JDRDNG3O0rOH6h59bhyARnDTpmQ",
      }),
    })
  };
  deferredCredential = {
    body: Joi.object({
      issuerDid: Joi.string()
        .description("The issuer DID")
        .example("did:ebsi:zvHWX359A3CvfJnCYaAiAde"),
      issuerUri: Joi.string()
        .description("The issuer URI")
        .example("https://my.example.issuer/issuer"),
      privateKeyJwk: privateKeyJwk
        .description("Private Keys in JSON Web Key (JWK) to sign the VC")
        .example({
          kty: "EC",
          x: "ujcuaJoOpnBxYYtlipyFQIahB5GDafNWO1TE2MR7YUI",
          y: "QOSoMUrerJI_kk5X34ACrmLB9adRstwmCWtdGYa_QKg",
          crv: "P-256",
          d: "V2Mgya-Tq13ltrW2JDRDNG3O0rOH6h59bhyARnDTpmQ",
        }),
      publicKeyJwk: publicKeyJwk.description("Public Key in JSON Web Key (JWK)").example({
        kty: "EC",
        x: "ujcuaJoOpnBxYYtlipyFQIahB5GDafNWO1TE2MR7YUI",
        y: "QOSoMUrerJI_kk5X34ACrmLB9adRstwmCWtdGYa_QKg",
        crv: "P-256",
        d: "V2Mgya-Tq13ltrW2JDRDNG3O0rOH6h59bhyARnDTpmQ",
      }),
    })
  }
}

const privateKeyJwk = Joi.object({
  kty: Joi.string().valid("RSA", "EC").required(),
  n: Joi.string().when("kty", { is: "RSA", then: Joi.required() }),
  e: Joi.string().when("kty", { is: "RSA", then: Joi.required() }),
  d: Joi.string().required(),
  crv: Joi.string().when("kty", {
    is: "EC",
    then: Joi.valid("P-256", "P-384", "P-521").required(),
  }),
  x: Joi.string().when("kty", { is: "EC", then: Joi.required() }),
  y: Joi.string().when("kty", { is: "EC", then: Joi.required() }),
  kid: Joi.string(),
  alg: Joi.string(),
  use: Joi.string(),
}).options({ allowUnknown: false });

const publicKeyJwk = Joi.object({
  kty: Joi.string().valid("RSA", "EC").required(),
  n: Joi.string().when("kty", { is: "RSA", then: Joi.required() }),
  e: Joi.string().when("kty", { is: "RSA", then: Joi.required() }),
  crv: Joi.string().when("kty", {
    is: "EC",
    then: Joi.valid("P-256", "P-384", "P-521").required(),
  }),
  x: Joi.string().when("kty", { is: "EC", then: Joi.required() }),
  y: Joi.string().when("kty", { is: "EC", then: Joi.required() }),
  kid: Joi.string(),
  alg: Joi.string(),
  use: Joi.string(),
}).options({ allowUnknown: false });
