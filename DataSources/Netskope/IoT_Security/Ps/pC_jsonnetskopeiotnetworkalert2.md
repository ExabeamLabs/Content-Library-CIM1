#### Parser Content
```Java
{
Name = json-netskope-iot-network-alert-2
  Conditions = [""""packet_alerts":""", """"category":"Misc activity"""", """"signature":"""", """"title":"""" ]

json-netskope-iot-events = {
  Vendor = Netskope
  Product = IoT Security
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """"source":"({host}[^"]{1,2000})"""",
    """"timestamp":"({time}[^"]{1,2000})"""",
    """"title":"({alert_name}[^"]{1,2000})"""",
    """"signature":"({alert_type}[^"]{1,2000})"""",
    """"severity":"({alert_severity}[^"]{1,2000})"""",
    """"id":"({alert_id}[^"]{1,2000})"""",
    """"description":"({additional_info}[^"]{1,2000})"""",
    """"source":\{[^=]{1,2000}?"ip":"({src_ip}[A-Fa-f\d.:]{1,2000})"""",
    """"source":\{[^=]{1,2000}?"host_name":"({src_host}[\w.-]{1,2000})"""",
    """"source":\{[^=]{1,2000}?"port":"({src_port}[\w.-]{1,2000})"""",
    """"source":\{[^=]{1,2000}?"mac":"({src_mac}[\w.-]{1,2000})"""",
    """"source":\{[^=]{1,2000}?"country":"({src_country}[\w.-]{1,2000})"""",
    """"destination":\{[^=]{1,2000}?"ip":"({dest_ip}[A-Fa-f\d.:]{1,2000})"""",
    """"destination":\{[^=]{1,2000}?"port":"({dest_port}[\w.-]{1,2000})"""",
    """"destination":\{[^=]{1,2000}?"mac":"({dest_mac}[\w.-]{1,2000})"""",
    """"destination":\{[^=]{1,2000}?"country":"({dest_country}[\w.-]{1,2000})"""",
    """"source":\{[^=]{1,2000}?"os":"({os}[^"]{1,2000})"""",
  
}
```