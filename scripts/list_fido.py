import hid, json
for d in hid.enumerate():
    print(hex(d['vendor_id']), hex(d['product_id']), d.get('usage_page'), d.get('interface_number'), d.get('product_string'))