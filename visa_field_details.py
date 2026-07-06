#!/usr/bin/env python3
"""
visa_field_details.py
======================
Value-level detail lookups for the VisaNet Authorization-Only ISO 8583
parser (visa.py).

visa.py + this file answer two different questions:
  - visa.py's describe_label()      -> "what IS this field/subfield?"
  - this file's get_value_detail()  -> "what does THIS VALUE of it mean?"

STATUS / COVERAGE:
This spec runs ~45,000 lines with value/code tables spread across
~130+ top-level fields and their subfields. This file transcribes the
value tables for every field the live parser (visa.py's FIELD_DEFS)
actually surfaces and that carries a defined, enumerable code - i.e.
fields 3, 22, 25, 26, 39, 44 (subfields 1-15), 53, 54, 59, 60, 62
(subfields 1-26), 63 (subfields 1,3,4,19), 70, 91, 101, 104 (dataset
57), 111 (dataset 01), and 126 (subfields 9,10,13,15,18,19,20).

DELIBERATELY NOT (yet) covered, and why:
  - F18 (Merchant Category Code) / F19,20,68,69 (ISO 3166 country
    codes) / F49-51 (ISO 4217 currency codes): these are large,
    externally standardized code sets (ISO 18245 / ISO 3166-1 / ISO
    4217) reused verbatim from those standards rather than transcribed
    from Visa's own tables - point at those standards instead of
    duplicating thousands of entries here.
  - F34 datasets 02/03/04/06/07/4A, F55 EMV tag *bit-level* meanings
    (e.g. individual TVR/CVM bits), F56, F111 datasets other than 01,
    F123, F127 variants, F134/138-143: real value tables exist in the
    spec for many of these, but they aren't in visa.py's FIELD_DEFS /
    decode path at all (the parser doesn't currently split them out),
    so a value-lookup here would have nothing live to attach to. Ask
    and I'll pull the relevant tables in the same pass as wiring up
    the decoder for that field.

Every entry below is sourced from the "Field N.M - Valid Values" /
"Table NNN" sections of visanet-authorization-only-online-messages-
technical-specifications.md (20 April 2026 edition).
"""

# ---------------------------------------------------------------------------
# Simple code -> meaning tables (used for fields that are just an
# enumerated code: look the raw digit/string straight up)
# ---------------------------------------------------------------------------

VALUE_TABLES = {

    # ---- Field 3 (Processing Code) subtables, spec Tables 34/35/36, p.97-98 ----
    "F3.TXN_TYPE": {  # positions 1-2
        "00": "Goods/Service Purchase - POS transaction only.",
        "01": "Cash Disbursement (e.g., withdrawal/cash advance) - Debit.",
        "10": "Account Funding.",
        "11": "Quasi-Cash Transaction - Debit, or Internet Gambling Transaction.",
        "20": "Return of Goods - Credit, Credit Voucher or Merchandise Return Authorization.",
        "26": "Original Credit.",
        "28": "Load and Activation / Load.",
        "30": "Balance/Available Funds Inquiry.",
        "34": "ATM Mini Statement.",
        "38": "Fee Inquiry.",
        "39": "Eligibility Inquiry.",
        "40": "Cardholder Account Transfer (ATM).",
        "50": "Bill Payment (U.S. only).",
        "53": "Payment (U.S. only).",
        "70": "PIN Change (ATM).",
        "72": "PIN Unblock (ATM) / Activation (POS).",
    },
    "F3.ACCT_FROM": {  # positions 3-4
        "00": "Not Applicable or Not Specified.",
        "10": "Savings Account.",
        "20": "Checking Account.",
        "30": "Credit Card Account.",
        "35": "Deferred Debit Account.",
        "36": "Charge Account.",
        "40": "Universal Account (represented by a cardholder identification number).",
        "60": "Prepaid Account.",
        "70": "Employee Benefit.",
    },
    "F3.ACCT_TO": {  # positions 5-6
        "00": "Not Applicable.",
        "10": "Savings Account.",
        "20": "Checking Account.",
        "30": "Credit Card Account.",
        "40": "Universal Account (represented by a cardholder identification number).",
    },

    # ---- Field 22 (POS Entry Mode) subtables, spec Tables 44/45/46, p.132-133 ----
    "F22.PAN_ENTRY": {  # positions 1-2
        "00": "Unknown or terminal not used.",
        "01": "Manual (key entry).",
        "02": "Visa: Magnetic stripe read; CVV checking may not be possible. "
              "PLUS: Track 2 contents read, but transaction not eligible for CVV checking.",
        "03": "Optical code.",
        "04": "Reserved for future use.",
        "05": "Contact integrated circuit card read using VSDC chip data rules; Online CAM "
              "authentication method; iCVV checking possible.",
        "06": "Reserved for future use.",
        "07": "Contactless device-read-originated using qVSDC chip data rules; Online CAM "
              "authentication method; iCVV checking possible.",
        "10": "Credential on file: transaction initiated using a credential previously stored on file.",
        "90": "Magnetic stripe read and exact content of Track 1 or Track 2 included (CVV check possible).",
        "91": "Contactless device-read-originated using magnetic stripe data rules; dCVV checking "
              "possible; Online CAM checking possible for MSD CVN 17 only.",
        "95": "Integrated circuit card read; CVV or iCVV checking may not be possible.",
    },
    "F22.PIN_CAPABILITY": {  # position 3
        "0": "Unknown.",
        "1": "Terminal can accept and forward online PINs.",
        "2": "Terminal cannot accept and forward online PINs.",
        "8": "Terminal PIN pad down.",
        "9": "Reserved for future use.",
    },
    "F22.FILL": {"0": "Unused (fill)."},  # position 4

    # ---- Field 25 - POS Condition Code, spec Table 47, p.135-137 ----
    "F25": {
        "00": "Normal transaction of this type: card and cardholder present at the merchant "
              "outlet (face-to-face transactions).",
        "01": "Cardholder not present.",
        "02": "Unattended cardholder-activated terminal or ATM transaction: unattended "
              "cardholder-activated environment, or ATM with PIN data present (Field 52).",
        "03": "Merchant suspicious of transaction (or card): may be occurring on lost, stolen, "
              "or counterfeit card.",
        "05": "Cardholder present, card not present: card data maintained on file for billing.",
        "06": "Preauthorization (only full-service acquirers initiate 0100 preauthorization "
              "requests). Not used in the 0100 preauthorization request itself.",
        "08": "Mail, telephone, recurring, advance, or installment order. Also used for recurring "
              "direct marketing payment transactions (see Fields 60.8 / 126.13).",
        "11": "Suspected fraud. Not applicable in this message family.",
        "12": "Security. Not applicable in this message family.",
        "51": "Request for account number verification, address verification, CVV2 verification, "
              "anticipated amount verification, or eligibility - without requesting authorization.",
        "59": "E-commerce request through public network (e.g. the Internet).",
        "71": "Card present, magnetic stripe cannot be read (key-entered) - U.S. only, POS transactions only.",
    },

    # ---- Field 39 - Response Code, spec Table 66, p.180-185 ----
    "F39": {
        "00": "Approval and completed successfully. Accepted and processed. [Category: Approval]",
        "01": "Refer to card issuer. [Category 4]",
        "02": "Refer to card issuer, special condition. [Category 4]",
        "03": "Invalid merchant. [Category 2]",
        "04": "Pick up card (no fraud). [Category 1 - never reattempt]",
        "05": "Do not honor. [Category 4]",
        "06": "Error. [Category 4]",
        "07": "Pick up card, special condition (fraud account). [Category 1 - never reattempt]",
        "10": "Partial approval. [Category: Approval]",
        "11": "Approved (V.I.P.). [Category: Approval] Not returned in responses; converted to 00.",
        "12": "Invalid transaction. [Category 1 - never reattempt]",
        "13": "Invalid amount, or currency conversion field overflow. [Category 4]",
        "14": "Invalid account number (no such number): no modulus 10 check, not a valid length "
              "for issuer, not in positive PIN Verification file, or separator in wrong position. "
              "[Category 1 - never reattempt]",
        "15": "No such issuer (first 8 digits of account number do not relate to an issuing "
              "identifier). [Category 1 - never reattempt]",
        "19": "Re-enter transaction. [Category 2]",
        "21": "No action taken. [Not applicable]",
        "25": "Unable to locate record in file. [Not applicable]",
        "28": "File is temporarily unavailable for update or inquiry. [Not applicable]",
        "39": "No credit account. [Category 2]",
        "41": "Lost card, pick up card (fraud account). [Category 1 - never reattempt]",
        "43": "Stolen card, pick up (fraud account). [Category 1 - never reattempt]",
        "46": "Closed account. [Category 1 - never reattempt]",
        "51": "Not sufficient funds. [Category 2]",
        "52": "No checking account. [Category 2]",
        "53": "No savings account. [Category 2]",
        "54": "Expired card or expiration date missing. [Category 3 - revalidate before reattempt]",
        "55": "PIN incorrect or missing. [Category 3 - revalidate before reattempt]",
        "57": "Transaction not permitted to cardholder (used by the switch when the requested "
              "function is not allowed for the product or card type). [Not applicable]",
        "58": "Transaction not allowed at terminal. [Category 4]",
        "59": "Suspected fraud. [Category 2]",
        "61": "Exceeds approval amount limit. [Category 2]",
        "62": "Restricted card (card invalid in region or country). [Category 2]",
        "63": "Security violation (source not correct issuer). [Not applicable]",
        "64": "Transaction does not fulfill AML requirement. [Category 4]",
        "65": "Exceeds withdrawal frequency limit. [Category 2]",
        "70": "PIN data required. [Category 3 - revalidate before reattempt]",
        "74": "Different value than that used for PIN encryption errors. [Category 4]",
        "75": "Allowable number of PIN-entry tries exceeded. [Category 2]",
        "76": "Unsolicited reversal - reversal with no original transaction in history; V.I.P. "
              "unable to match the reversal to an original message. [Not applicable]",
        "78": "Blocked, first used or special condition - new cardholder not activated or card "
              "temporarily blocked. [Category 2]",
        "79": "Reversed (by switch). [Category 4]",
        "80": "No financial impact (used in reversal responses to declined originals). [Category 4]",
        "81": "Cryptographic error found in PIN (security module error during PIN decryption). "
              "[Category 4]",
        "82": "Negative online CAM, dCVV, iCVV, CVV, CAVV, dCVV2, TAVV, or DTVV results, or "
              "offline PIN authentication interrupted. [Category 3 - revalidate before reattempt]",
        "85": "No reason to decline a request for address verification, CVV2 verification, or "
              "credit voucher/merchandise return. [Not applicable]",
        "86": "Cannot verify PIN (e.g. no PVV on file). [Category 2]",
        "91": "Issuer unavailable or switch inoperative (STIP not applicable/available), or "
              "time-out with no STIP, or issuer-supplied to decline authorization on its own "
              "behalf; causes decline at POS. [Category 2]",
        "92": "Financial institution or intermediate network facility cannot be found for "
              "routing (receiving institution ID invalid). [Not applicable]",
        "93": "Transaction cannot be completed - violation of law. [Category 2]",
        "94": "Duplicate transmission: message contains tracing-data values duplicating a "
              "previously submitted transaction. [Not applicable]",
        "96": "System malfunction. [Category 2]",
        "1A": "Additional customer authentication required. [Category 3 - revalidate before "
              "reattempt] V.I.P. converts to 05 if the acquirer is not activated to receive it.",
        "5C": "Transaction not supported / blocked by issuer. [Category 2, reattempt allowed]",
        "6P": "Verification data failed. [Category 3 - revalidate before reattempt]",
        "9G": "Blocked by cardholder / contact cardholder. [Category 2, reattempt allowed]",
        "B1": "Surcharge amount not permitted on Visa cards or EBT food stamps (U.S. acquirers "
              "only; POS only, not ATM). [Not applicable]",
        "N0": "Force STIP - issuer requests this single transaction be routed to STIP because it "
              "cannot perform authorization itself. [Category 4]",
        "N3": "Cash service not available (not allowed for ATM cash disbursement). [Category 2]",
        "N4": "Cash request exceeds issuer or approved limit. [Category 2]",
        "N7": "Decline for CVV2 failure. [Category 3 - revalidate before reattempt]",
        "N8": "Transaction amount exceeds pre-authorized approval amount. [Not applicable]",
        "P5": "Denied PIN unblock - PIN change or unblock request declined by issuer (ATM only). "
              "[Not applicable]",
        "P6": "Denied PIN change - requested PIN unsafe (ATM only). [Not applicable]",
        "Q1": "Card authentication failed, or offline PIN authentication interrupted. Issuers can "
              "receive this from STIP but should not return it themselves. [Not applicable]",
        "R0": "Stop this payment. [Category 1 - never reattempt]",
        "R1": "Stop all future payments. [Category 1 - never reattempt]",
        "R2": "Transaction does not qualify for Visa PIN. [Not applicable]",
        "R3": "Stop all merchants. [Category 1 - never reattempt]",
        "Z3": "Unable to go online; offline-declined. Used only by V.I.P. in non-cardholder "
              "requests such as advices; issuers should never use this code. [Category 4]",
        "Z5": "Valid account but amount not supported. Used only in 0110 responses to "
              "Anticipated Amount Verification transactions. [Not applicable]",
        "Z6": "Invalid use of MCC - correct and reattempt. [Category 2]",
    },

    # ---- Field 44.1 - Response Source/Reason Code, spec Table 70, p.200 ----
    "F44.1": {
        "0": "Advice of ASAF change initiated by Global Customer Assistance Service (GCAS) or "
             "Automatic Cardholder Database Update (Auto-CDB) Service.",
        "1": "Response provided by STIP because the request was timed out by the switch "
             "(Assured Transaction Response/ATR) or the response contained invalid data.",
        "2": "Response provided by STIP because the transaction amount is below the sliding "
             "dollar limit (PACM processing), or in response to a verification request.",
        "4": "Response provided by STIP because the issuer was not available for processing.",
        "5": "Response provided by the issuer.",
        "7": "Reversal message matched to the original authorization request message.",
        "8": "No matching original authorization request message found (does not guarantee "
             "the original wasn't received).",
        "A": "Automated fuel dispenser advice.",
        "B": "Response provided by STIP: transaction met Visa Transaction Advisor Service criteria.",
        "C": "Response provided by STIP for conditions not otherwise listed (see Field 63.4).",
        "H": "Exceeds acquirer settlement exposure cap.",
        "V": "Authorization obtained via VisaNet (issuer or STIP response).",
        "^": "Data is not present (space).",
    },

    # ---- Field 44.2 - Address Verification Result Code, spec Table 71, p.203 ----
    "F44.2": {
        "Y": "AVS full match (postal/ZIP code and street address match).",
        "A": "AVS street address match only (partial match).",
        "Z": "AVS postal/ZIP code match only (partial match).",
        "N": "AVS non-match.",
        "R": "AVS indeterminate outcome (retry) - issuer participates in AVS but was "
             "unavailable, or the submitted address data was blank/null/non-printable.",
        "U": "AVS unable to verify - issuer could not perform AVS, does not participate, or "
             "holds no address data on file for this account (also used when Visa performs AVS "
             "on the issuer's behalf but no address data was provisioned).",
    },

    # ---- Field 44.3 - Additional Token Response Information, spec Table 72, p.204 ----
    "F44.3": {
        "1": "Token Program.",
        " ": "Not Applicable.",
    },

    # ---- Field 44.4 - Extended STIP Reason Code, spec Table 73, p.205 ----
    "F44.4": {
        "2": "Missing expiration date.",
        "3": "VSDC default response code decline.",
        "4": "CVV2 default response code decline.",
        "5": "Declined key-entered transaction in STIP.",
        "6": "Risky country response code.",
        "7": "Interlink pre-auth completion history.",
        "8": "OCT rule decline.",
        "9": "Domestic PIN at POS set to decline in STIP.",
        "A": "AA score greater than value specified by issuer.",
        "B": "AA score greater than STIP MCC threshold.",
        "C": "Processed by Smarter STIP.",
        "F": "Amount exceeds cardholder available balance (N/A for ATM transactions).",
    },

    # ---- Field 44.5 - CVV/iCVV Results Code, spec Table 74, p.206 ----
    "F44.5": {
        "": "CVV, iCVV, or dCVV was not verified (blank / not present).",
        "0": "CVV, iCVV, or dCVV could not be verified.",
        "1": "CVV, iCVV, dCVV, or Online CAM failed verification, or Offline PIN authentication "
             "was interrupted.",
        "2": "CVV, iCVV, dCVV, or Online CAM passed verification.",
        "3": "Not Applicable.",
    },

    # ---- Field 44.7 - PACM Diversion Reason Code, spec Table (p.209) ----
    "F44.7": {
        "A": "Exceeded capacity.",
    },

    # ---- Field 44.8 - Card Authentication Results Code, spec Table 76, p.211 ----
    "F44.8": {
        "": "Online CAM was not performed, or a system/cryptographic problem prevented "
            "verification (e.g. issuer not participating). (blank / not present)",
        "1": "The Authorization Request Cryptogram (ARQC) was checked but failed verification.",
        "2": "The ARQC was checked and passed verification.",
    },

    # ---- Field 44.10 - CVV2 and dCVV2 Result Codes, spec Table 77, p.214 ----
    "F44.10": {
        "M": "CVV2/dCVV2 Match: Visa or the issuer verified the value and it matched.",
        "N": "CVV2/dCVV2 No Match: Visa or the issuer verified the value and it did not match.",
        "P": "Not Performed: participates in CVV2/dCVV2 but did not verify due to system "
             "settings, the transaction being declined, or STIP responding to an "
             "issuer-unavailable condition.",
        "S": "System Error (Retry): could not perform verification because the merchant did "
             "not supply the required information (CVV2/dCVV2 value, expiry date).",
        "U": "Unable to Verify: issuer not participating in CVV2/dCVV2, or has not provided "
             "Visa the encryption keys needed to verify.",
    },

    # ---- Field 44.13 - CAVV Results Code, spec Table 82, p.220-221 ----
    "F44.13": {
        "": "CAVV not present or not verified; issuer has not selected CAVV verification. (blank)",
        "0": "CAVV could not be verified, or CAVV data was not provided when expected.",
        "1": "CAVV failed verification - authentication.",
        "2": "CAVV passed verification - authentication.",
        "3": "CAVV passed verification - attempted authentication (3DS Authentication Results "
             "Code 07 from the Issuer Attempts Server; issuer attempts CAVV key was used).",
        "4": "CAVV failed verification - attempted authentication (3DS Authentication Results "
             "Code 07 from the Issuer Attempts Server; issuer attempts CAVV key was used).",
        "5": "Not used (reserved for future use).",
        "6": "CAVV not verified, issuer not participating in CAVV verification (Visa-generated "
             "only; rejected by V.I.P. with reject code 0193).",
        "7": "CAVV failed verification - attempted authentication (3DS Authentication Results "
             "Code 07 from Visa Attempts Service; Visa CAVV attempts key was used).",
        "8": "CAVV passed verification - attempted authentication (3DS Authentication Results "
             "Code 07 from Visa Attempts Service; Visa CAVV attempts key was used).",
        "9": "CAVV failed verification - attempted authentication (3DS Authentication Results "
             "Code 08, issuer ACS unavailable; Visa CAVV attempts key was used).",
        "A": "CAVV passed verification - attempted authentication (3DS Authentication Results "
             "Code 08, issuer ACS unavailable; Visa CAVV attempts key was used).",
        "B": "CAVV passed CAVV verification, no liability shift.",
        "C": "CAVV was not verified - attempted authentication (Visa-generated only; rejected "
             "by V.I.P. with reject code 0193).",
        "D": "CAVV was not verified - cardholder authentication (Visa-generated only; rejected "
             "by V.I.P. with reject code 0193).",
    },

    # ---- Field 44.14 - Response Reason Code (Mastercard advice codes), Table 83, p.222-223 ----
    "F44.14": {
        "M001": "New account information available. (Mastercard DE 48.84 code 01)",
        "M002": "Cannot approve at this time, try again later. (Mastercard DE 48.84 code 02)",
        "M003": "Do not try again. (Mastercard DE 48.84 code 03)",
        "M004": "Token requirements not fulfilled for this token type. (Mastercard DE 48.84 code 04)",
        "M021": "Payment Cancellation Service (Full Service use only). (Mastercard DE 48.84 code 21)",
        "M022": "Merchant does not qualify for product code. (Mastercard DE 48.84 code 22)",
        "M024": "Retry after 1 hour (Mastercard use only). (Mastercard DE 48.84 code 24)",
        "M025": "Retry after 24 hours (Mastercard use only). (Mastercard DE 48.84 code 25)",
        "M026": "Retry after 2 days (Mastercard use only). (Mastercard DE 48.84 code 26)",
        "M027": "Retry after 4 days (Mastercard use only). (Mastercard DE 48.84 code 27)",
        "M028": "Retry after 6 days (Mastercard use only). (Mastercard DE 48.84 code 28)",
        "M029": "Retry after 8 days (Mastercard use only). (Mastercard DE 48.84 code 29)",
        "M030": "Retry after 10 days (Mastercard use only). (Mastercard DE 48.84 code 30)",
        "M040": "Consumer non-reloadable prepaid card. (Mastercard DE 48.84 code 40)",
        "M041": "Consumer single-use virtual card number. (Mastercard DE 48.84 code 41)",
        "M042": "Sanctions Scoring Service: score exceeds applicable threshold value. "
                "(Mastercard DE 48.84 code 42)",
        "M043": "Consumer multi-use virtual card number. (Mastercard DE 48.84 code 43)",
    },

    # ---- Field 53 - Security Codes (Usage 1), spec Tables 103-106, p.254 ----
    "F53.SECURITY_FORMAT": {"20": "Zone encryption."},
    "F53.PIN_ALGO": {"01": "ANSI DES."},
    "F53.PIN_BLOCK_FORMAT": {
        "01": "Based on the PIN, PIN length, and selected rightmost digits of the account "
              "number, XOR'd with pad characters 0 and F. Conforms to ISO Format 0.",
        "02": "Based on the PIN, PIN length, and a user-specified numeric pad character (Docutel).",
        "03": "Based on the PIN and the F pad character (Diebold-IBM).",
    },
    "F53.PIN_ZONE_KEY_INDEX": {
        "00": "Reserved for future use.",
        "01": "Working Key 1 is to be changed or used.",
        "02": "Working Key 2 is to be changed or used.",
    },

    # ---- Field 59 - National POS Geographic Data (state/province), Tables 140/141, p.305-306 ----
    "F59.STATE": {
        "01": "Alabama", "02": "Alaska", "04": "Arizona", "05": "Arkansas", "06": "California",
        "08": "Colorado", "09": "Connecticut", "10": "Delaware", "11": "District of Columbia",
        "12": "Florida", "13": "Georgia", "15": "Hawaii", "16": "Idaho", "17": "Illinois",
        "18": "Indiana", "19": "Iowa", "20": "Kansas", "21": "Kentucky", "22": "Louisiana",
        "23": "Maine", "24": "Maryland", "25": "Massachusetts", "26": "Michigan",
        "27": "Minnesota", "28": "Mississippi", "29": "Missouri", "30": "Montana",
        "31": "Nebraska", "32": "Nevada", "33": "New Hampshire", "34": "New Jersey",
        "35": "New Mexico", "36": "New York", "37": "North Carolina", "38": "North Dakota",
        "39": "Ohio", "40": "Oklahoma", "41": "Oregon", "42": "Pennsylvania",
        "44": "Rhode Island", "45": "South Carolina", "46": "South Dakota", "47": "Tennessee",
        "48": "Texas", "49": "Utah", "50": "Vermont", "51": "Virginia", "53": "Washington",
        "54": "West Virginia", "55": "Wisconsin", "56": "Wyoming",
        "99": "U.S. military base, embassies, traveling merchants",
        "60": "Alberta (Canada)", "61": "British Columbia (Canada)", "62": "Manitoba (Canada)",
        "63": "New Brunswick (Canada)", "64": "Newfoundland and Labrador (Canada)",
        "65": "Northwest Territories (Canada)", "66": "Nova Scotia (Canada)",
        "67": "Ontario (Canada)", "68": "Prince Edward Island (Canada)", "69": "Quebec (Canada)",
        "70": "Saskatchewan (Canada)", "71": "Yukon (Canada)", "72": "Nunavut (Canada)",
    },

    # ---- Field 62.1 - Authorization Characteristics Indicator, Table 154/155, p.328-330 ----
    "F62.1": {
        "A": "CPS-qualified: card present, magnetic stripe read/sent (or Retail-2/Commercial "
             "Card key-entered with other requirements met); signature obtained; CVV "
             "requested if stripe present.",
        "C": "CPS-qualified (AFD): meets requirements for A, plus merchant name/location "
             "present and UCAT indicator set, no signature required.",
        "E": "CPS-qualified: meets requirements for A, plus enriched merchant/ATM owner "
             "name and location present; also used for Retail-2 key-entered, Commercial "
             "Card, and Visa Cashback.",
        "F": "CPS-qualified: meets CPS/Account Funding requirements.",
        "J": "CPS-qualified: meets CPS/Recurring Bill Payment Program requirements (U.S. only).",
        "K": "CPS-qualified: card present with key entry.",
        "M": "CPS-qualified: meets national payment service requirements with no address "
             "verification (Direct Marketing).",
        "S": "CPS-qualified: meets requirements for a 3-D Secure CAVV attempt transaction.",
        "U": "CPS-qualified: meets basic CPS/E-Commerce requirements and 3-D Secure CAVV "
             "data is present.",
        "V": "CPS-qualified: meets address verification requirements (Direct Marketing / "
             "Transport, card-not-present).",
        "W": "CPS-qualified: meets basic CPS/E-Commerce requirements but the 3-D Secure "
             "CAVV transmission was nonverified.",
        "R": "CPS-qualified: meets Direct Marketing recurring payment qualification without "
             "address verification (U.S. only; certain healthcare/developing-market MCCs may "
             "use R to bypass AVS).",
        "I": "CPS-qualified: incremental authorization qualified for CPS (Hotel/Auto Rental).",
        "P": "CPS-qualified: meets Preferred Customer requirements (Card Not Present: "
             "Hotel/Auto Rental and Transport).",
        "N": "Not CPS-qualified (returned to acquirer when the requested ACI did not qualify).",
        "T": "Not CPS-qualified - U.S. transactions only (including non-U.S. acquirer to U.S. issuer).",
        "D": "Not CPS-requested/qualified but the transaction is eligible for EDQP (Enhanced "
             "Data Qualification Program). If the acquirer sends D in the request, V.I.P. "
             "ignores/drops it.",
    },

    # ---- Field 62.3 - CPS Downgrade Reason Codes, Table 158, p.339-340 ----
    "F62.3": {
        "AN": "Account number is missing in track data.",
        "AV": "Address verification is not requested.",
        "CD": "Transaction must be key-entered and track data cannot be present.",
        "CK": "Key-entered field requirements invalid for the field in question.",
        "CN": "Cash is not qualified for CPS/Retail.",
        "CV": "Acquirer is not in CVV or iCVV full participation mode.",
        "CX": "Not monitored by or participating in CVV (temporary exception list).",
        "ED": "Expiration date is missing in track data.",
        "EM": "Enriched Merchant Name and Location are not present.",
        "I2": "CVV2 result code not U, M, or P.",
        "IC": "Invalid Country Code.",
        "IM": "Invalid MCC.",
        "IP": "Invalid Purchase Identifier.",
        "IS": "Invalid State Code.",
        "MC": "Not participating in multicurrency.",
        "NA": "Transaction is not approved.",
        "NE": "E-commerce transaction did not qualify.",
        "NP": "Acquirer is not participating in CPS.",
        "NS": "Non-secure electronic commerce transaction.",
        "NT": "Not participating in CPS/ATM.",
        "NV": "The transaction is not a Visa card transaction.",
        "PI": "CVV2 Authorization Request Data is not 1, 2, or 9.",
        "RV": "Invalid ACI for this service.",
        "TA": "Account number does not match track data.",
        "TD": "Expiration date does not match track data.",
        "TI": "Transaction identifier invalid.",
        "02": "Primary Account Number missing.",
        "18": "Merchant category code (MCC) is missing (Field 18).",
        "22": "POS Entry Mode is not 90, 01, 02, 05, or 95 (card present).",
        "42": "Field 42 - Card Acceptor ID Code is not present.",
        "59": "Merchant ZIP Code is missing or zero for the U.S. acquirer (Field 59).",
    },

    # ---- Field 62.4 - Market-Specific Data Identifier, Table 159, p.342 ----
    "F62.4": {
        "A": "Auto Rental.",
        "B": "Bill Payment.",
        "E": "Electronic commerce transaction aggregation.",
        "H": "Hotel.",
        "J": "B2B invoice payments (not applicable for Interlink).",
        "M": "Healthcare (medical).",
        "N": "Failed Market-Specific Data edit, or not applicable.",
        "T": "Transit (healthcare transactions only).",
        "X": "Extended Authorization (not applicable for Interlink).",
    },

    # ---- Field 62.7 - CPS Purchase Identifier position 1, Table 161, p.345 ----
    "F62.7.FORMAT": {
        "1": "Order Number (Visa Fleet) - Prompted Fleet Work Order Number.",
        "5": "Invoice Number (Visa Fleet) - Prompted Invoice Number.",
        "6": "Pay ID for OCT transactions (Request to Pay OCT).",
    },

    # ---- Field 62.23 - Product ID, Table 167, p.355-356 ----
    "F62.23": {
        "A": "Visa Traditional", "AX": "American Express", "B": "Visa Traditional Rewards",
        "C": "Visa Signature", "D": "Visa Signature Preferred", "DI": "Discover",
        "DN": "Diners", "DU": "China UnionPay International", "E": "Proprietary ATM",
        "F": "Visa Classic", "F2": "Visa Installment Credential",
        "F3": "Visa Installment Credential Standard", "G": "Visa Business",
        "G1": "Visa Signature Business", "G2": "Visa Value Business (not applicable to Interlink)",
        "G3": "Visa Business Enhanced / Visa Platinum Business", "G4": "Visa Infinite Business",
        "G5": "Visa Business Rewards", "I": "Visa Infinite", "I1": "Visa Infinite Privilege",
        "I2": "Visa Ultra High Net Worth (UHNW)", "I3": "Visa Infinite Plus (Canada only)",
        "J3": "Visa Healthcare (U.S. region only) / Visa Workplace Benefits", "JC": "JCB",
        "K": "Visa Corporate T&E", "K1": "Visa Government Corporate T&E", "L": "Visa Electron",
        "L1": "Visa Value (not applicable to Interlink)", "M": "Mastercard",
        "N": "Visa Platinum", "N1": "Visa Rewards", "N2": "Visa Select", "P": "Visa Gold",
        "Q": "Private Label", "Q2": "Private Label Basic", "Q3": "Private Label Standard",
        "Q4": "Private Label Enhanced", "Q5": "Private Label Specialized",
        "Q6": "Private Label Premium", "R": "Proprietary", "S": "Visa Purchasing",
        "S1": "Visa Purchasing with Fleet / Visa Fleet (Canada only)",
        "S2": "Visa Government Purchasing", "S3": "Visa Government Purchasing With Fleet",
        "S4": "Visa Commercial Agriculture", "S5": "Visa Commercial Transport",
        "S6": "Visa Commercial Marketplace", "U": "Visa TravelMoney", "V": "V PAY",
        "W": "Visa Direct Payouts to Wallets (space-padded code)",
        "W1": "Visa Direct Payouts to Bank Accounts",
        "X": "Visa Commercial Choice Travel (space-padded code)",
        "X1": "Visa Commercial Choice Omni",
    },

    # ---- Field 62.25 - Spend Qualified Indicator, Tables 168/169, p.358-359 ----
    "F62.25": {
        " ": "Spend-processing does not apply.",
        "B": "Base spend-assessment threshold defined by Visa has been met.",
        "J": "Not Qualified Tier 5.",
        "K": "Not Qualified Tier 4.",
        "L": "Not Qualified Tier 3.",
        "M": "Not Qualified Tier 2.",
        "N": "Spend-assessment threshold defined by Visa has not been met.",
        "Q": "Qualified: spend-assessment threshold defined by Visa has been met.",
        "R": "Qualified tier 2.",
        "S": "Qualified tier 3.",
        "T": "Qualified tier 4.",
        "U": "Qualified tier 5.",
        "V": "Qualified tier 6.",
        "W": "Qualified tier 7.",
        "1": "Tier 1 (Visa Business cards, Puerto Rico and U.S.).",
        "2": "Tier 2 (Visa Business cards, Puerto Rico and U.S.).",
        "3": "Tier 3 (Visa Business cards, Puerto Rico and U.S.).",
        "4": "Tier 4 (Visa Business cards, Puerto Rico and U.S.).",
        "5": "Tier 5 (Visa Business cards, Puerto Rico and U.S.).",
    },

    # ---- Field 62.26 - Account Status, Table 170, p.360 ----
    "F62.26": {"R": "Regulated.", "N": "Non-regulated."},

    # ---- Field 63.3 - Authorization-Only Message Reason Codes, Table 179, p.370 ----
    "F63.3": {
        "2104": "Acquirer authorization advice: used in acquirer-generated 0120 advices when "
                "an online authorization was not performed (not used in preauth completion advices).",
        "2501": "Transaction voided by customer.",
        "2502": "Transaction not completed.",
        "2503": "No confirmation from point of service. (VisaNet sends this to the issuer if the "
                "acquirer omits this field in reversal messages.)",
        "2504": "Partial dispense by ATM (misdispense) or POS partial reversal.",
        "5120": "Value-Added Tax Code, sent in value-added-tax-related original OCTs.",
    },

    # ---- Field 63.4 - STIP/Switch Reason Code, Table 180, p.372-374 ----
    "F63.4": {
        "9001": "The issuer is signed off. (STIP Processing Advice)",
        "9002": "The issuer was signed off by the switch. (STIP Processing Advice)",
        "9011": "The line to issuer is down. (STIP Processing Advice)",
        "9012": "Forced STIP because of N0 (Force STIP) original response from issuer. (STIP Processing Advice)",
        "9020": "The response from issuer timed out. (STIP Processing Advice)",
        "9021": "Alternate PCR used for Auth Destination. (STIP Processing Advice)",
        "9022": "PACM-diverted. (STIP Processing Advice)",
        "9024": "Transaction declined due to Visa Payment Controls (VPC) rule. (STIP Processing Advice)",
        "9025": "Declined by Selective Acceptance Service. (STIP Processing Advice)",
        "9026": "Reviewed by the Visa Transaction Advisor Service: additional authentication "
                "required. (STIP Processing Advice)",
        "9027": "Declined by token provisioning service. (STIP Processing Advice)",
        "9028": "The issuer requested CDB update through GCAS. (Switch-Generated File Update Advice)",
        "9030": "Account listed in ASAF via Auto-CDB, or updated by ASAF Downgrade feature. "
                "(STIP Processing Advice)",
        "9031": "Original processed in stand-in. (STIP Processing Advice)",
        "9033": "Declined due to active account management threshold exceeded. (STIP Processing Advice)",
        "9034": "Unable to deliver response to originator. (STIP Processing Advice)",
        "9035": "Process recurring payment in STIP. (STIP Processing Advice)",
        "9037": "Declined by Visa CTC (Consumer Transaction Controls) service. (STIP Processing Advice)",
        "9038": "Merchandise return authorization processed in STIP. (STIP Processing Advice)",
        "9039": "VFC decline due to limited acceptance merchant. (STIP Processing Advice)",
        "9041": "There was a PIN verification error. (STIP Processing Advice)",
        "9042": "Offline PIN authentication was interrupted. (STIP Processing Advice)",
        "9045": "Switch was unable to translate the PIN. (STIP Processing Advice)",
        "9047": "Declined by Real-Time Decisioning (RTD) processing. (STIP Processing Advice)",
        "9048": "Invalid CVV with the All Respond Option. (STIP Processing Advice)",
        "9049": "Account Verification - Visa Verify Only. (STIP Processing Advice)",
        "9050": "Source or destination does not participate in this service. (STIP-Generated Advice)",
        "9054": "There is an invalid CAM. (STIP Processing Advice)",
        "9055": "Merchant program identifier missing. (STIP Processing Advice)",
        "9057": "STIP approved transaction due to Real Time Decisioning (RTD). (STIP Processing Advice)",
        "9058": "Approved by VFC Managed Transaction Decline Safeguard. (STIP Processing Advice)",
        "9061": "Internal system error or other switch-detected error condition. (Switch-Detected Error)",
        "9063": "Transaction declined, processing requirements not met (regulated-jurisdiction "
                "VIC unavailable/ineligible/misrouted; no STIP advice generated). (STIP Processing Advice)",
        "9064": "Transaction declined; invalid payment channel for card type. (STIP Processing Advice)",
        "9070": "Declined by Account Screen; issuer participates in All Respond. (STIP-Generated Advice)",
        "9091": "Dispute financial. (STIP Processing Advice)",
        "9095": "Issuer notification of token vault provisioned or status change. (STIP Processing Advice)",
        "9102": "Switch generated this 0420 reversal advice because an approval response "
                "could not be delivered to the acquirer. VE only. (Switch-Generated Reversal Advice)",
        "9103": "An approval response could not be delivered to the acquirer because the "
                "issuer timed out. (Switch-Generated Reversal Advice)",
        "9200": "This AA Score Request transaction was automatically processed by STIP "
                "(Visa internal use only). (AA Scoring Request)",
        "9201": "Decline due to VSPS (Visa Stop Payment Service). (STIP-Decline Advice)",
        "9202": "Decline due to issuer country exclusion list. (STIP-Decline Advice)",
        "9203": "Decline due to Office of Foreign Assets Control (OFAC) embargo. (STIP-Decline Advice)",
        "9204": "Cashback processing error. (STIP-Decline Advice)",
        "9205": "Invalid CAVV with Visa Verify and decline options (V and W). (STIP-Decline Advice)",
        "9206": "Mod-10 check failure. (STIP-Decline Advice)",
        "9207": "Issuer does not support gambling transactions. (STIP-Decline Advice)",
        "9208": "Declined because issuing identifier, routing identifier, or token account "
                "range is blocked. (STIP-Decline Advice)",
        "9209": "Declined because issuer does not support transaction type. (STIP-Decline Advice)",
        "9210": "Declined because of issuer participation options. (STIP-Decline Advice)",
        "9211": "Declined because acquirer does not support the service requested. (STIP-Decline Advice)",
        "9212": "Declined due to fraud condition. (STIP-Decline Advice)",
        "9213": "Declined because call-out to an external service timed out. (STIP-Decline Advice)",
        "9214": "Declined because of error return from call-out to external service. (STIP-Decline Advice)",
        "9215": "Declined because issuer blocked specific POS entry mode. (STIP-Decline Advice)",
        "9216": "Non-device-based token used to personalize. (STIP-Decline Advice)",
        "9217": "Issuer tokenization data sent is invalid or incorrect length (FCI > 128, IAD "
                "not 15, or IAD first byte not 00). (STIP-Decline Advice)",
        "9218": "Product subtype is MB (Interoperable mobile branchless) but BAI is not MP, or "
                "vice versa. (STIP-Decline Advice)",
        "9219": "Merchant Blocking Service Decline Reason Code. (STIP-Decline Advice)",
        "9220": "Device binding request could not be completed. (STIP-Decline Advice)",
        "9221": "Declined due to PFD acquirer-specific ecosystem block. (STIP-Decline Advice)",
        "9222": "Declined due to PFD issuer-specific ecosystem block. (STIP-Decline Advice)",
        "9223": "Declined due to client-tailored block - acquirer/merchant. (STIP-Decline Advice)",
        "9224": "Declined due to client-tailored block - issuer. (STIP-Decline Advice)",
        "9225": "Declined due to ecosystem PFD fraud block (non-specific). (STIP-Decline Advice)",
        "9226": "Declined due to PFD block for other risk factors (non-specific). (STIP-Decline Advice)",
        "9227": "dCVV2 validation failed and authorization request declined. (STIP-Decline Advice)",
        "9229": "Declined due to domestic regulations. (STIP-Decline Advice)",
        "9230": "RAM Fraud Rule Decline without advice (Visa internal use only). (STIP-Decline Advice)",
        "9258": "Declined by VFC Managed Transaction Decline Safeguard. (STIP-Decline Advice)",
        "9302": "Exceeds issuer settlement risk exposure cap. (STIP-Decline Advice)",
        "9303": "Exceeds acquirer settlement risk exposure cap. (STIP-Decline Advice)",
        "9999": "Authorization provision environment mismatch. (STIP-Decline Advice)",
    },

    # ---- Field 70 - Network Management Information Code, Table 181, p.378 ----
    "F70": {
        "071": "Sign on to the V.I.P. System (Message Types 0800/0810).",
        "072": "Sign-off from the V.I.P. System (Message Types 0800/0810).",
        "078": "Start transmission (Message Types 0800/0810).",
        "079": "Stop transmission (Message Types 0800/0810).",
        "101": "Key change request (Message Types 0800/0810).",
        "160": "Request for a new acquirer working key, acquirer to switch (Message Types 0800/0810).",
        "161": "Request for a new issuer working key, issuer to switch (Message Types 0800/0810).",
        "162": "Deliver a new acquirer working key, switch to acquirer (Message Types 0800/0810).",
        "163": "Deliver a new issuer working key, switch to issuer (Message Types 0800/0810).",
        "164": "Update acquirer key (Message Types 0800/0810).",
        "165": "Update issuer key (Message Types 0800/0810).",
        "301": "Echo test - can be initiated by the VIC or the client (Message Types 0800/0810).",
        "870": "Request by Debit Processing Services (DPS) for AA scoring results - Visa use "
               "only (Message Types 0600/0610).",
        "889": "Supplemental Commercial Card Data - CEMEA region only (Message Types "
               "0600/0610/0620/0630).",
        "890": "Issuer token advice (Message Types 0620/0630).",
        "892": "Account name inquiry issuer confirmation advice (Message Types 0620/0630).",
        "951": "VSDC code for issuer authentication failure or issuer script results advice "
               "(Message Types 0620/0630).",
    },

    # ---- Field 91 - File Update Code, Table 183, p.385 ----
    "F91": {
        "1": "Add. Except as noted, add new record if one does not exist. For ASAF records, an "
             "existing record is updated as a change.",
        "2": "Change. Except as noted, change the record (ASAF: add if it doesn't exist). Not "
             "supported by VSPS, AVS, or ANI.",
        "3": "Delete. Delete record.",
        "4": "Replace. Add new record if none exists, or replace existing record. Supported by VSPS.",
        "5": "Inquire. Send a copy of the record.",
    },

    # ---- Field 101 - File Name, Table 184, p.393 ----
    "F101": {
        "A2": "Address Verification File.",
        "D1": "dCVV2 Participation.",
        "E2": "Account Screen Authorization File (ASAF).",
        "L1": "ALP inquiries to the CDB (0302 messages) - no explicit CDB file name.",
        "M9": "Merchant Central File (Merchant Central File Service participants only).",
        "N2": "Account name inquiry.",
        "PAN": "Card Data.",
        "PAR": "Payment Account Reference.",
        "PF1": "Portfolio File.",
        "PFD": "Payment Fraud Disruption Allow List.",
        "P2": "PIN Verification File.",
        "R2": "Risk-Level File.",
        "SB": "Spending balance.",
    },

    # ---- Field 126.10, Position 1 - Presence Indicator, Table 284, p.627 ----
    "F126.10.PRESENCE": {
        "0": "CVV2 value not provided - merchant is not providing a CVV2 value for verification.",
        "1": "CVV2 value is present - merchant is providing the CVV2 value for verification.",
        "3": "dCVV2 validation performed (V.I.P. checks position 3 for dCVV2; only valid for "
             "messages sent to issuers).",
        "4": "dCVV2 checked and failed; CVV2 validation performed instead (only valid for "
             "messages sent to issuers subscribing to CVV2 fallback).",
    },
    "F126.10.RESPONSE_TYPE": {
        "0": "Only the normal response code in Field 39 should be returned. (V.I.P. default "
             "when position 2 is neither 0 nor 1.)",
        "1": "The normal response code in Field 39 and the CVV2 result in Field 44.10 should "
             "be returned.",
    },

    # ---- Field 126.13 - POS Environment, Table 286, p.634 ----
    "F126.13": {
        "C": "Credential on File (initial storage) / Unscheduled Card on File (subsequent "
             "merchant-initiated transactions).",
        "I": "Installment payment.",
        "R": "Recurring payment: cardholder and merchant agreed to periodic billing (e.g. "
             "utility bills, magazines).",
    },

    # ---- Field 126.15 - Mastercard UCAF Collection Indicator, Table 287, p.635 ----
    "F126.15": {
        "0": "Non-authenticated payment, Identity Check with failed authentication, or "
             "Tokenized Payment with Dynamic Token Verification Code (DTVC).",
        "1": "Merchant supports UCAF collection; UCAF data must be present (Field 126.16 "
             "must contain an attempt AAV for Mastercard Identity Check).",
        "2": "Merchant supports UCAF collection; UCAF data must be present (fully "
             "authenticated AAV; DSRP cryptogram optional for tokenized transactions). "
             "Includes Cardholder-Initiated Transactions for authentication.",
        "3": "Merchant supports UCAF collection; UCAF (Mastercard Assigned Static "
             "Accountholder Authentication Value) data must be present.",
        "4": "Merchant shares authentication data within authorization; UCAF data must be "
             "present (Insights AAV for Mastercard Identity Check).",
        "5": "Reserved for future use.",
        "6": "Merchant risk-based decisioning.",
        "7": "Partial shipment or recurring payment / merchant-initiated transaction "
             "(Field 126.16 only required for Identity Check).",
        "8": "Reserved for future use.",
        "9": "Reserved for future use.",
    },

    # ---- Field 126.18, positions 2-6 - Digital Entity Identifier, Table 289, p.638 ----
    "F126.18.ENTITY_ID": {
        "VCIND": "Visa Click to Pay - transaction processed through Visa Click to Pay "
                 "(India domestic use only).",
    },

    # ---- Field 126.20 - 3-D Secure Indicator, Table 290, p.640 ----
    "F126.20": {
        "0": "3DS 1.0.2 or prior; all authentication methods; or 3DS 1.0.2 frictionless flow.",
        "1": "Challenge flow using static passcode.",
        "2": "Challenge flow using One Time Passcode (OTP) via SMS.",
        "3": "Challenge flow using OTP through key fob or card reader.",
        "4": "Challenge flow using OTP through an app.",
        "5": "Challenge flow using OTP through any other method.",
        "6": "Challenge flow using Knowledge Based Authentication (KBA).",
        "7": "Challenge flow using Out of Band (OOB) authentication with biometric method.",
        "8": "Challenge flow using OOB authentication with app login method.",
        "9": "Challenge flow using OOB authentication with any other method.",
        "A": "Challenge flow using any other authentication method.",
        "B": "Unrecognized authentication method.",
        "C": "Push confirmation.",
    },

    # ---- Field 60.1-10 (kept from prior version; spec Table 143, p.317-320) ----
    "F60.1": {
        "0": "Unspecified. Identifies the basic point-of-service electronic terminal being used.",
        "1": "Unattended cardholder-activated, no authorization, below-floor-limit transaction "
             "(not for zero floor markets). Should not be used in an authorization.",
        "2": "ATM. (Europe region only: also used for an authorization transaction with chip and "
             "PIN capability from an ATM or unattended cardholder-activated terminal.)",
        "3": "Unattended cardholder-activated, authorized transaction (online-authorized or "
             "offline-approved, e.g. movie/game rentals, automated retail).",
        "4": "Electronic cash register.",
        "5": "Unattended customer terminal.",
        "7": "Telephone device.",
        "8": "Reserved.",
        "9": "mPOS device used to originate a transaction on an open network.",
    },
    "F60.2": {
        "0": "Unknown codes.",
        "1": "Terminal not used.",
        "2": "Magnetic stripe read capability.",
        "3": "QR code.",
        "4": "OCR read capability.",
        "5": "Contact chip, magnetic-stripe, or proximity-capable terminal (can read both chip "
             "and magnetic stripe). Used regardless of whether Visa contactless is also supported.",
        "6": "Reserved for future use.",
        "7": "Reserved for future use.",
        "8": "Proximity-read-capable: can read a Visa contactless proximity chip but not a "
             "contact chip. Used only if Visa contactless is supported and contact chip is not.",
        "9": "Terminal does not read card data.",
    },
    "F60.3": {
        "0": "Not applicable to fallback transactions. For VSDC transactions, this subfield must "
             "contain 0 or be excluded from the message.",
        "1": "Fallback transaction: initiated from a magnetic stripe with a service code "
             "beginning with 2 or 6, and the last read at a VSDC terminal was a successful chip "
             "read or was not a chip transaction.",
        "2": "Fallback transaction: initiated at a chip-capable terminal from a magnetic stripe "
             "with service code 2 or 6, and the previous transaction at that terminal was an "
             "unsuccessful chip read.",
    },
    "F60.4": {
        "0": "Default value.",
        "1": "Purchase of Central Bank Digital Currency (CBDC) or tokenized deposits.",
        "2": "Purchase of Stablecoin (Fiat-backed).",
        "3": "Purchase of Blockchain Native Token/Coin.",
        "4": "Purchase of non-fungible token (NFT).",
        "7": "Purchase of Cryptocurrency (also covers OCT/AFT sale or conversion of "
             "cryptocurrency to fiat currency).",
        "8": "Quasi-Cash.",
        "9": "Payment on existing debt.",
    },
    "F60.5": {"00": "Not applicable. Not currently used in the technical specifications."},
    "F60.6": {
        "0": "Not applicable; subsequent subfields are present. When an Early Data or Full Data "
             "option acquirer submits Early Data, this subfield must contain 0 or be excluded.",
        "1": "Sent by acquirers using the standard third bitmap or Field 55 to submit chip data.",
        "2": "Sent by acquirers using the expanded third bitmap for their chip data. Applies only "
             "to acquirers - V.I.P. changes it to 1 before forwarding the request to the issuer.",
        "3": "Inserted by V.I.P. (not the acquirer); also downgrades the transaction by dropping "
             "the chip data section.",
        "4": "Inserted by V.I.P. based on the presence of a token-based transaction.",
    },
    "F60.7": {
        "0": "Fill for Field 60.7, or subsequent subfields are present.",
        "1": "Acquirer indicates that Card Authentication may not be reliable.",
        "2": "V.I.P. indicates acquirer inactive for Card Authentication.",
        "3": "V.I.P. indicates issuer inactive for Card Authentication.",
    },
    "F60.8": {
        "00": "Not applicable: mail/telephone/e-commerce indicator not relevant to the transaction.",
        "01": "Single transaction of a mail/phone order (not recurring/installment). In the US "
              "region this may also indicate one bill payment, card-present or card-absent.",
        "02": "Recurring transaction (US-region-originated acquirers). Other regions must use "
              "Field 126.13 - POS Environment value 'R' to identify a recurring payment.",
        "03": "Installment payment (US-region-originated acquirers): one purchase billed in "
              "multiple charges over time. Other regions must use Field 126.13 value 'I'.",
        "04": "Unknown classification: other mail order (type of mail/telephone order unknown).",
        "05": "Secure electronic commerce transaction: authenticated using a Visa-approved "
              "protocol such as 3-D Secure. Field 25 must contain 59 for this value to be valid.",
        "06": "Non-authenticated security transaction at a 3-D Secure-capable merchant: "
              "merchant attempted cardholder authentication via 3-D Secure but could not "
              "complete it because the issuer or cardholder does not participate.",
        "07": "Non-authenticated security transaction: data encryption used for security, but "
              "cardholder authentication was not performed via a Visa-approved protocol.",
        "08": "Non-secure transaction: no data protection used. (Not allowed in the Europe region.)",
        "09": "Reserved: not valid for authorization requests.",
    },
    "F60.9": {
        "0": "Not specified.",
        "1": "Signature.",
        "2": "Online PIN.",
        "3": "Unattended terminal, no PIN pad.",
        "4": "Mail/Telephone/Electronic Commerce.",
    },
    "F60.10": {
        "0": "Not applicable: indicators not set for this transaction, or the field does not "
             "apply. Issuers not activated to receive Field 60.10 may see 0 here if Field 60.9 "
             "is present in the request.",
        "1": "Terminal accepts partial authorization responses.",
        "2": "Estimated amount: terminal does not support partial authorization responses.",
        "3": "Estimated amount, and terminal accepts partial authorization responses.",
    },

    # ---- Field 111, Dataset 01, Tag 8E (Persistent FX Eligible), Table 225, p.502 ----
    "F111.01.8e": {
        "0": "Transaction not eligible for the Persistent FX service.",
        "1": "Transaction eligible for the Persistent FX service.",
    },
}

VALUE_TABLES["F111.01.8E"] = VALUE_TABLES["F111.01.8e"]

# Field 104, Usage 2, Dataset 57, Tag 01 - Business Application Identifier (Table 192, p.412)
VALUE_TABLES["F104.57.01"] = {
    "AA": "Account to account (sender and recipient are the same person).",
    "AL": "AFT or OCT eligibility.",
    "BB": "Business to business.",
    "BI": "Money transfer - bank-initiated.",
    "BP": "Non-card bill payment.",
    "CB": "Consumer bill payment.",
    "CD": "Cash deposit.",
    "CI": "Cash in (Mobile Push Payment transactions only; N/A for Interlink).",
    "CO": "Cash out (Mobile Push Payment transactions only; N/A for Interlink).",
    "CP": "Card bill payment.",
    "FD": "Funds disbursement (general).",
    "FT": "Funds transfer.",
    "GD": "Government disbursement.",
    "GP": "Gambling payout (other than online gambling).",
    "LA": "Liquid Assets.",
    "LO": "Loyalty and offers (original credit transactions only).",
    "MD": "Merchant disbursement.",
    "MI": "Merchant Initiated OCT for Faster Refund.",
    "MP": "Merchant payment (Mobile Push Payment transactions only; N/A for Interlink).",
    "OG": "Online gambling payout.",
    "PD": "Payroll/pension disbursement.",
    "PG": "Payment to government.",
    "PP": "Person to person (sender and recipient are not the same person).",
    "PS": "Payment for goods and services (general).",
    "RP": "Request to pay.",
    "TU": "Top-up for enhanced prepaid loads.",
    "VA": "Visa Accept.",
    "WT": "Wallet transfer.",
}


# ---------------------------------------------------------------------------
# Fields whose "detail" needs decomposition/logic rather than a flat lookup
# (multi-position fixed fields, computed values, or free-text fields).
# ---------------------------------------------------------------------------

def _lookup(table_key, code, field_label):
    table = VALUE_TABLES.get(table_key, {})
    meaning = table.get(code)
    if meaning is None:
        return f"Unrecognized code '{code}' for {field_label} (not in the confirmed spec value table)."
    return meaning


def _detail_f3(value: str) -> str:
    digits = value.strip()
    if len(digits) != 6:
        return f"Processing Code (6 digits expected: txn type + acct-from + acct-to); got '{value}'."
    txn, acct_from, acct_to = digits[0:2], digits[2:4], digits[4:6]
    return (
        f"Positions 1-2 (Transaction Type) = {txn}: {_lookup('F3.TXN_TYPE', txn, 'F3 txn type')} | "
        f"Positions 3-4 (Account Type From) = {acct_from}: {_lookup('F3.ACCT_FROM', acct_from, 'F3 acct-from')} | "
        f"Positions 5-6 (Account Type To) = {acct_to}: {_lookup('F3.ACCT_TO', acct_to, 'F3 acct-to')}"
    )


def _detail_f22(value: str) -> str:
    digits = value.strip()
    if len(digits) != 4:
        return f"POS Entry Mode (4 digits expected: PAN/date entry + PIN capability + fill); got '{value}'."
    pan_mode, pin_cap, fill = digits[0:2], digits[2], digits[3]
    return (
        f"Positions 1-2 (PAN/Date Entry Mode) = {pan_mode}: {_lookup('F22.PAN_ENTRY', pan_mode, 'F22 entry mode')} | "
        f"Position 3 (PIN Entry Capability) = {pin_cap}: {_lookup('F22.PIN_CAPABILITY', pin_cap, 'F22 PIN capability')} | "
        f"Position 4 (Fill) = {fill}: {_lookup('F22.FILL', fill, 'F22 fill')}"
    )


def _detail_f26(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    try:
        n = int(digits)
    except ValueError:
        return f"POS PIN Capture Code: expected a number 04-12, got '{value}'."
    if 4 <= n <= 12:
        return f"Maximum number of PIN characters the point-of-service device can accept ({n})."
    return f"Value {n} is outside the valid range (04-12 per spec Field 26 - Valid Values)."


def _detail_f39(value: str) -> str:
    return _lookup("F39", value.strip().upper(), "F39 response code")


def _detail_f53(value: str) -> str:
    digits = value.strip()
    if len(digits) < 8:
        return f"Security-Related Control Information: expected at least 8 digits, got '{value}'."
    fmt, algo, block_fmt, key_idx = digits[0:2], digits[2:4], digits[4:6], digits[6:8]
    return (
        f"Positions 1-2 (Security Format Code) = {fmt}: {_lookup('F53.SECURITY_FORMAT', fmt, 'F53 security format')} | "
        f"Positions 3-4 (PIN Encryption Algorithm) = {algo}: {_lookup('F53.PIN_ALGO', algo, 'F53 PIN algorithm')} | "
        f"Positions 5-6 (PIN Block Format) = {block_fmt}: {_lookup('F53.PIN_BLOCK_FORMAT', block_fmt, 'F53 PIN block format')} | "
        f"Positions 7-8 (PIN Zone Key Index) = {key_idx}: {_lookup('F53.PIN_ZONE_KEY_INDEX', key_idx, 'F53 PIN zone key index')} | "
        f"Positions 9-16 must be zero-filled by the acquirer."
    )


_F54_AMOUNT_TYPES = {
    "00": "Not applicable or not specified.",
    "01": "Deposit account current ledger (posted) balance, or credit card open-to-buy amount.",
    "02": "Deposit account current available balance, or credit card customer credit limit.",
    "4P": "Additional transaction fee 1.",
    "4Q": "Additional transaction fee 2.",
    "42": "Amount surcharge (POS surcharge / ATM access fee).",
    "4D": "Fee Amount (Domestic Fee Inquiry).",
    "4E": "Requested Amount (Domestic Fee Inquiry).",
    "57": "Original amount (Partial Authorization).",
    "95": "Visa Money Transfer (VMT) - AFT Foreign Exchange Fees.",
}
_F54_ACCOUNT_TYPES = {
    "00": "Not applicable or not specified.",
    "10": "Savings account.",
    "20": "Checking account.",
    "30": "Credit card account.",
    "40": "Universal account.",
    "28": "Load transaction.",
    "72": "Activation transaction.",
}


def _detail_f54(value: str) -> str:
    digits = value.strip()
    if len(digits) < 4:
        return ("Additional Amounts field. Structure: positions 1-2 Account Type, 3-4 Amount "
                f"Type, 5-7 Currency Code, 8 Amount Sign, 9-20 Amount. Raw value '{value}' too "
                "short to decompose.")
    acct_type, amt_type = digits[0:2], digits[2:4]
    parts = [
        f"Positions 1-2 (Account Type) = {acct_type}: "
        f"{_F54_ACCOUNT_TYPES.get(acct_type, 'Not in the confirmed table for this usage.')}",
        f"Positions 3-4 (Amount Type) = {amt_type}: "
        f"{_F54_AMOUNT_TYPES.get(amt_type, 'Not in the confirmed table for this usage.')}",
    ]
    if len(digits) >= 7:
        parts.append(f"Positions 5-7 (Currency Code) = {digits[4:7]}")
    if len(digits) >= 8:
        sign = digits[7]
        sign_meaning = {"C": "Credit to cardholder / positive.", "D": "Debit to cardholder / negative."}
        parts.append(f"Position 8 (Amount Sign) = {sign}: {sign_meaning.get(sign, 'unrecognized sign')}")
    if len(digits) >= 20:
        parts.append(f"Positions 9-20 (Amount) = {digits[8:20]}")
    return " | ".join(parts)


def _detail_f59(value: str) -> str:
    code = value.strip()
    meaning = VALUE_TABLES["F59.STATE"].get(code)
    if meaning:
        return f"{meaning} (U.S. state or Canadian province code)."
    return (f"Code '{code}' not in the U.S. state / Canadian province table - likely a ZIP/postal "
            "code or non-US/CA geographic value instead (Field 59 carries a state code for US/CA, "
            "ZIP/postal code otherwise).")


def _detail_f62_1(value: str) -> str:
    return _lookup("F62.1", value.strip().upper(), "F62.1 ACI code")


def _detail_f62_2(value: str) -> str:
    return (
        "Right-justified, V.I.P.-generated Transaction Identifier (TID), unique to this "
        "original authorization/financial request. Links the original message to later "
        "messages (exception item processing, clearing records, reversals). Not a coded "
        "field - this is the literal TID value."
    )


def _detail_f62_3(value: str) -> str:
    return _lookup("F62.3", value.strip().upper(), "F62.3 downgrade reason")


def _detail_f62_4(value: str) -> str:
    return _lookup("F62.4", value.strip().upper(), "F62.4 market-specific data identifier")


def _detail_f62_5(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    try:
        n = int(digits)
    except ValueError:
        return f"Duration: expected 01-99, got '{value}'."
    if n == 0:
        return "Invalid: zero is not allowed for Field 62.5 (Duration)."
    if n == 1:
        return "1 day anticipated for the auto rental/hotel stay (also used for no-show authorizations)."
    return f"{n} days anticipated for the auto rental or hotel stay."


def _detail_f62_7(value: str) -> str:
    fmt = value.strip()[:1] if value.strip() else ""
    meaning = _lookup("F62.7.FORMAT", fmt, "F62.7 purchase identifier format")
    rest = value[1:] if len(value) > 1 else ""
    return f"Position 1 (Format) = {fmt}: {meaning} | Positions 2-26 (Purchase Identifier) = '{rest}'"


def _detail_f62_20(value: str) -> str:
    return "Merchant Verification Value (MVV): 10 hexadecimal digits (0-9, A-F), not packed BCD."


def _detail_f62_23(value: str) -> str:
    return _lookup("F62.23", value.strip().upper(), "F62.23 product ID")


def _detail_f62_25(value: str) -> str:
    return _lookup("F62.25", value if value.strip() else " ", "F62.25 spend qualified indicator")


def _detail_f62_26(value: str) -> str:
    return _lookup("F62.26", value.strip().upper(), "F62.26 account status")


def _detail_f63_1(value: str) -> str:
    code = value.strip()
    table = {"0000": "Visa determines the network and program rules.", "0002": "Visa.", "0004": "Plus."}
    if code in table:
        return table[code]
    return f"Unrecognized Network ID code '{code}' (spec Table 173 only defines 0000/0002/0004)."


def _detail_f63_3(value: str) -> str:
    return _lookup("F63.3", value.strip(), "F63.3 message reason code")


def _detail_f63_4(value: str) -> str:
    return _lookup("F63.4", value.strip(), "F63.4 STIP/switch reason code")


def _detail_f70(value: str) -> str:
    return _lookup("F70", value.strip(), "F70 network management code")


def _detail_f91(value: str) -> str:
    return _lookup("F91", value.strip(), "F91 file update code")


def _detail_f101(value: str) -> str:
    return _lookup("F101", value.strip().upper(), "F101 file name")


def _detail_f104_57_01(value_hex_or_text: str) -> str:
    """Accepts either the already-decoded 2-char text (e.g. 'WT') or the
    raw EBCDIC hex bytes as parsed by visa.py's current hex-passthrough
    rendering of F104 (e.g. 'E6E3')."""
    text = value_hex_or_text.strip()
    candidate = text.upper()
    table = VALUE_TABLES["F104.57.01"]
    if candidate in table:
        return f"{candidate} = {table[candidate]}"
    try:
        decoded = bytes.fromhex(text).decode("cp037").upper()
        if decoded in table:
            return f"{decoded} = {table[decoded]} (raw hex {text} decodes to EBCDIC '{decoded}')"
    except Exception:
        pass
    return f"Unrecognized Business Application Identifier value '{value_hex_or_text}'."


def _detail_f111_01_80(value: str) -> str:
    return (
        "Exchange Rate Provider - the source of the FX rate. For the Persistent FX service "
        "this is literally the text 'Visa Inc., Exchange Rate'."
    )


def _detail_f111_01_81(value: str) -> str:
    return "Rate Table ID - identifies the foreign exchange rate table used for currency conversion."


def _detail_f111_01_82(value: str) -> str:
    """Leftmost digit = number of decimal places to shift in from the
    right; remaining 7 digits are the rate (spec Table 225, p.502)."""
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) != 8:
        return ("Exchange Rate: leftmost digit is the decimal-shift count, remaining 7 digits "
                f"are the rate (unable to compute - expected 8 digits, got '{value}').")
    shift = int(digits[0])
    rate_digits = digits[1:]
    if shift == 0:
        rate_str = rate_digits
    else:
        rate_str = rate_digits.rjust(shift, "0")
        int_part = rate_str[:-shift] or "0"
        frac_part = rate_str[-shift:]
        rate_str = f"{int_part}.{frac_part}"
    return (
        f"Exchange Rate from the table identified in Tag 81, no markup applied. Leftmost digit "
        f"'{shift}' = number of decimal positions to shift in from the right; remaining digits "
        f"'{rate_digits}' are the rate. Computed rate \u2248 {rate_str}."
    )


def _detail_f111_01_8e(value: str) -> str:
    return _lookup("F111.01.8e", value.strip(), "F111.01.8E Persistent FX Eligible Indicator")


def _detail_f126_9(value: str) -> str:
    return (
        "Multi-use field for Visa Secure e-commerce transactions; contains encrypted "
        "verification data whose exact structure depends on the service in use (3-D Secure "
        "CAVV, revised-format 3-D Secure CAVV, or American Express SafeKey/token processing). "
        "Rendered here as raw hex since the specific usage variant isn't distinguished by the "
        "parser yet."
    )


def _detail_f126_10(value: str) -> str:
    text = value if len(value) >= 2 else value.ljust(2)
    presence, resp_type = text[0], text[1]
    cvv2 = text[2:6] if len(text) >= 6 else text[2:]
    return (
        f"Position 1 (Presence Indicator) = {presence}: "
        f"{_lookup('F126.10.PRESENCE', presence, 'F126.10 presence indicator')} | "
        f"Position 2 (Response Type) = {resp_type}: "
        f"{_lookup('F126.10.RESPONSE_TYPE', resp_type, 'F126.10 response type')} | "
        f"Positions 3-6 (CVV2 Value) = '{cvv2}'"
    )


def _detail_f126_13(value: str) -> str:
    return _lookup("F126.13", value.strip().upper(), "F126.13 POS Environment")


def _detail_f126_15(value: str) -> str:
    return _lookup("F126.15", value.strip(), "F126.15 Mastercard UCAF Collection Indicator")


def _detail_f126_18(value: str) -> str:
    return (
        "Byte 1 fixed value 0x0B, bytes 2-6 Agent Unique ID (see F126.18.ENTITY_ID table, e.g. "
        "'VCIND' = Visa Click to Pay), bytes 7-11 Enabler Verification Value (5-char Visa-assigned "
        f"value), byte 12 reserved (0). Raw value: '{value}'."
    )


def _detail_f126_20(value: str) -> str:
    return _lookup("F126.20", value.strip().upper(), "F126.20 3-D Secure Indicator")


DETAIL_FUNCS = {
    "F3": _detail_f3,
    "F22": _detail_f22,
    "F26": _detail_f26,
    "F39": _detail_f39,
    "F53": _detail_f53,
    "F54": _detail_f54,
    "F59": _detail_f59,
    "F62.1": _detail_f62_1,
    "F62.2": _detail_f62_2,
    "F62.3": _detail_f62_3,
    "F62.4": _detail_f62_4,
    "F62.5": _detail_f62_5,
    "F62.7": _detail_f62_7,
    "F62.20": _detail_f62_20,
    "F62.23": _detail_f62_23,
    "F62.25": _detail_f62_25,
    "F62.26": _detail_f62_26,
    "F63.1": _detail_f63_1,
    "F63.3": _detail_f63_3,
    "F63.4": _detail_f63_4,
    "F70": _detail_f70,
    "F91": _detail_f91,
    "F101": _detail_f101,
    "F104.57.01": _detail_f104_57_01,
    "F111.01.80": _detail_f111_01_80,
    "F111.01.81": _detail_f111_01_81,
    "F111.01.82": _detail_f111_01_82,
    "F111.01.8e": _detail_f111_01_8e,
    "F111.01.8E": _detail_f111_01_8e,
    "F126.9": _detail_f126_9,
    "F126.10": _detail_f126_10,
    "F126.13": _detail_f126_13,
    "F126.15": _detail_f126_15,
    "F126.18": _detail_f126_18,
    "F126.20": _detail_f126_20,
}

# Direct-lookup labels: field/subfield whose value is looked up straight
# out of VALUE_TABLES under the same key (no decomposition needed).
_DIRECT_LOOKUP_LABELS = {
    "F25", "F44.1", "F44.2", "F44.3", "F44.4", "F44.5", "F44.7", "F44.8",
    "F44.10", "F44.13", "F44.14",
    "F60.1", "F60.2", "F60.3", "F60.4", "F60.5", "F60.6", "F60.7", "F60.8",
    "F60.9", "F60.10",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_NO_DETAIL_YET = (
    "N/A"
)


def get_value_detail(label: str, value: str) -> str:
    """
    Given a compact-format label (e.g. 'F60.1', 'F39', 'F104.57.01') and
    its already-decoded value string, return a human-readable detail line
    describing what that specific value means, per the VisaNet spec.

    Falls back to an honest "not covered yet" message rather than
    guessing, for anything not yet transcribed into this module.
    """
    if label in DETAIL_FUNCS:
        try:
            return DETAIL_FUNCS[label](value)
        except Exception as e:
            return f"<detail lookup error: {e}>"

    if label in _DIRECT_LOOKUP_LABELS:
        return _lookup(label, value.strip(), label)

    table = VALUE_TABLES.get(label)
    if table is not None:
        meaning = table.get(value) or table.get(value.upper()) or table.get(value.lower())
        if meaning is not None:
            return meaning
        return f"Unrecognized value '{value}' for {label} (not in the confirmed spec value table)."

    return _NO_DETAIL_YET


def format_field_report(rows) -> str:
    """
    Given a list of (label, description, raw_hex, value) rows - the same
    shape visa.py's parse_message_full() produces - render the
    'F60.1: Terminal Type / * Value: `0` / * Detail: ...' style report.
    """
    lines = []
    for label, desc, _raw_hex, value in rows:
        title = desc.split(" - ")[-1]
        if ":" in title and title.split(":")[0].strip().lower().startswith("subfield"):
            title = title.split(":", 1)[1].strip()
        lines.append(f"{label}: {title}")
        lines.append("")
        lines.append(f"* Value: `{value}`")
        lines.append(f"* Detail: {get_value_detail(label, value)}")
        lines.append("")
    return "\n".join(lines)
