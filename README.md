# cvereporter
Create a report on CVE in modules of interest to you

## REST API

<code>POST /updatedb/ : Update local DB</code><br>

### Example

    {
    "first": "2015",
    "last": "2016"
    }

All fields are required

<code>POST /reports/ : Create report</code><br>

### Example

    {
    "first": "2015",
    "last": "2016",
    "part": "o",
    "vendor": "microsoft",
    "product": "windows_7",
    "version": "",
    "update": "",
    "edition": "",
    "language": "",
    "sw_edition": "",
    "target_sw": "",
    "target_hw": "",
    "other": ""
    }

The fields "first", "last", "part", "vendor" and "product" are required.

Next feature:
- take a target from the list
