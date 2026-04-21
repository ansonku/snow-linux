#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>



// hwmon attributes
static int stub_temp_value = 50000; // 50.000 degree C
static ssize_t stub_temp_show(struct device *dev, struct device_attribute *devattr, char *buf)
{
    return sprintf(buf, "%d\n", stub_temp_value);
}
static ssize_t stub_temp_store(struct device *dev, struct device_attribute *devattr, const char *buf, size_t count)
{
    int ret;
    ret = kstrtoint(buf, 10, &stub_temp_value);
    if (ret < 0)
        return ret;
    return count;
}
static SENSOR_DEVICE_ATTR(temp1_input, 0644, stub_temp_show, stub_temp_store, 0);
static struct attribute *stub_temp_attrs[] = {
    &sensor_dev_attr_temp1_input.dev_attr.attr,
    NULL,
};

ATTRIBUTE_GROUPS(stub_temp);


// i2c device module registration
static int stub_temp_probe(struct i2c_client *client)
{
    struct device *hwmon_dev;
     hwmon_dev = devm_hwmon_device_register_with_groups(&client->dev, client->name, NULL, stub_temp_groups);
    if (IS_ERR(hwmon_dev))
        return PTR_ERR(hwmon_dev);
     return 0;
}
static const struct i2c_device_id stub_temp_id[] = {
    { "stub_temp_sensor", 0 },
    { }
};
MODULE_DEVICE_TABLE(i2c, stub_temp_id);
static struct i2c_driver stub_temp_driver = {
    .driver = {
        .name   = "stub_temp_sensor",
    },
    .probe      = stub_temp_probe,
    .id_table   = stub_temp_id,
};
module_i2c_driver(stub_temp_driver);



// MISC
MODULE_AUTHOR("Anson Ku <ansonku@gmail.com>");
MODULE_DESCRIPTION("Stub Temperature Sensor Driver");
MODULE_LICENSE("GPL");
