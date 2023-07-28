# -*- coding: utf-8 -*-

# Copyright (c) 2021-2022 Hewlett Packard Enterprise, Inc. All rights reserved.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
import os
import tempfile
import zipfile
import shutil
import sys
import time
import json
from string import ascii_lowercase
from random import choice
import redfish
import re
import traceback
import paramiko

__metaclass__ = type

from ansible_collections.community.general.plugins.module_utils.redfish_utils import RedfishUtils
from ansible.module_utils.basic import missing_required_lib

HAS_IPADDRESS = True
IPADDRESS_IMP_ERR = None
try:
    import ipaddress
except ImportError as e:
    IPADDRESS_IMP_ERR = traceback.format_exc()
    HAS_IPADDRESS = False

HAS_URLLIB3 = True
URLLIB3_IMP_ERR = None
try:
    import urllib3
except ImportError as e:
    URLLIB3_IMP_ERR = traceback.format_exc()
    HAS_URLLIB3 = False


class FwpkgError(Exception):
    """Baseclass for all fwpkg exceptions"""

    errcode = 1

    def __init__(self, message=None):
        Exception.__init__(self, message)


class TaskQueueError(FwpkgError):
    """Raised when there is an issue with the current order of taskqueue"""

    pass


class FirmwareUpdateError(FwpkgError):
    """Raised when there is an error while updating firmware"""

    pass


class UploadError(FwpkgError):
    """Raised when the component fails to download"""

    pass


class InvalidFileInputError(FwpkgError):
    """Raised when user enter an invalid file input"""

    pass


class IncompatibleiLOVersionError(FwpkgError):
    """Raised when iLo version is not compatible"""

    pass


class TimeOutError(FwpkgError):
    """Raised when the update service times out"""

    pass


class UnsuccesfulRequest(FwpkgError):
    """ Raised when a HTTP request in unsuccessful"""

    pass

def ilo_certificate_login(root_uri, module, cert_file, key_file):
    if not os.path.exists(cert_file):
        module.fail_json(msg="The client cert file does not exist in the provided path %s" % str(cert_file))

    if not os.path.exists(key_file):
        module.fail_json(msg="The client key file does not exist in the provided path %s" % str(key_file))

    try:
        http = urllib3.PoolManager(cert_reqs='CERT_NONE', cert_file=cert_file, key_file=key_file)
        cert_login = http.request('GET', root_uri + "/html/login_cert.html")
    except Exception as e:
        module.fail_json(msg="Server login with certificates failed: %s" % str(e))

    return cert_login.getheader('X-Auth-Token')

class iLOOemUtils(RedfishUtils):

    def __init__(self, creds, root_uri, timeout, module):
        super().__init__(creds, root_uri, timeout, module)

        if not HAS_IPADDRESS:
            self.module.fail_json(msg=missing_required_lib('ipaddress'), exception=IPADDRESS_IMP_ERR)

        if not HAS_URLLIB3:
            self.module.fail_json(msg=missing_required_lib('urllib3'), exception=URLLIB3_IMP_ERR)

    def preparefwpkg(self, fwpkg_file):

        imagefiles = []
        tempdir = tempfile.mkdtemp()

        try:
            zfile = zipfile.ZipFile(fwpkg_file)
            zfile.extractall(tempdir)
            zfile.close()
        except Exception as excp:
            raise InvalidFileInputError("Unable to unpack file. " + str(excp))

        files = os.listdir(tempdir)

        if "payload.json" in files:
            with open(os.path.join(tempdir, "payload.json"), encoding="utf-8") as pfile:
                data = pfile.read()
            payloaddata = json.loads(data)
        else:
            raise InvalidFileInputError(
                "Unable to find payload.json in fwpkg file.")

        comptype = self.get_comp_type(payloaddata)

        results = self.get_request(
            self.root_uri + self.service_root + "UpdateService/")
        if not results['ret']:
            raise UnsuccesfulRequest(
                "Request is not completed successfully. " + str(results))

        for device in payloaddata["Devices"]["Device"]:
            for firmwareimage in device["FirmwareImages"]:
                if firmwareimage["FileName"] not in imagefiles:
                    imagefiles.append(firmwareimage["FileName"])

        if comptype == 'A' and payloaddata['PackageFormat'] == 'FWPKG-v2':
            imagefiles = [fwpkg_file]

        return imagefiles, tempdir, comptype

    def get_comp_type(self, payloaddata):

        ctype = ""

        if "Uefi" in payloaddata["UpdatableBy"] and "RuntimeAgent" in payloaddata["UpdatableBy"]:
            ctype = "D"
        elif "UEFI" in payloaddata["UpdatableBy"] and "Bmc" in payloaddata["UpdatableBy"]:
            data = None
            results = self.get_request(
                self.root_uri + self.service_root + "UpdateService/")
            if not results['ret']:
                raise UnsuccesfulRequest(
                    "Request is not completed successfully. " + str(results))

            data1 = results['data']
            if "FirmwareInventory" in data1:
                results = self.get_request(
                    self.root_uri + data1["FirmwareInventory"]["@odata.id"])
                if not results['ret']:
                    raise UnsuccesfulRequest(
                        "Request is not completed successfully. " + str(results))
                data = results['data']
            if data is not None:
                type_set = None
                for fw in data:
                    for device in payloaddata["Devices"]["Device"]:
                        if fw["Oem"]["Hpe"].get("Targets") is not None:
                            if device["Target"] in fw["Oem"]["Hpe"]["Targets"]:
                                if fw["Updateable"] and (payloaddata['PackageFormat'] == 'FWPKG-v2'):
                                    ctype = "A"
                                    type_set = True
                                else:
                                    ctype = "C"
                                    type_set = True
                if type_set is None:
                    raise IncompatibleiLOVersionError(
                        "Cannot flash the component on this server, server is not VROC enabled\n"
                    )
        else:
            for device in payloaddata["Devices"]["Device"]:
                for image in device["FirmwareImages"]:
                    if "DirectFlashOk" not in list(image.keys()):
                        raise InvalidFileInputError(
                            "Cannot flash this firmware.")
                    if image["DirectFlashOk"]:
                        ctype = "A"
                        if image["ResetRequired"]:
                            ctype = "B"
                            break
                    elif image["UefiFlashable"]:
                        ctype = "C"
                        break
                    else:
                        ctype = "D"

        return ctype

    def findcompsig(self, comppath):
        compsig = ""

        cutpath = comppath.split(os.sep)
        _file = cutpath[-1]
        _file_rev = _file[::-1]
        filename = _file[: ((_file_rev.find(".")) * -1) - 1]

        try:
            location = os.sep.join(cutpath[:-1])
        except Exception as e:
            location = os.curdir

        if not location:
            location = os.curdir

        files = [
            f for f in os.listdir(location) if os.path.isfile(os.path.join(location, f))
        ]

        for filehndl in files:
            if filehndl.startswith(filename) and filehndl.endswith(".compsig"):
                if location != ".":
                    compsig = location + os.sep + filehndl
                else:
                    compsig = filehndl

                break

        return compsig

    def check_and_split(self, options):

        def check_file_rw(filename, rw):
            try:
                fd = open(filename, rw)
                fd.close()
            except IOError:
                raise InvalidFileInputError(
                    "The file '%s' could not be opened for upload" % filename
                )

        maxcompsize = 32 * 1024 * 1024
        filelist = []

        # Get the component filename
        t1, filename = os.path.split(options["component"])
        check_file_rw(os.path.normpath(options["component"]), "r")
        size = os.path.getsize(options["component"])

        if not options["componentsig"]:
            if not self.findcompsig(filename):
                return [(filename, options["component"], options["componentsig"], 0)]

        if size > maxcompsize:
            section = 1

            sigpath, t1 = os.path.split(options["componentsig"])
            check_file_rw(os.path.normpath(options["componentsig"]), "r")
            filebasename = filename[: filename.rfind(".")]
            tempfoldername = "bmn" + \
                "".join(choice(ascii_lowercase) for i in range(12))

            tempdir = os.path.join(sys.executable, tempfoldername)

            if not os.path.exists(tempdir):
                os.makedirs(tempdir)

            with open(options["component"], "rb") as component:
                while True:
                    data = component.read(maxcompsize)
                    if len(data) != 0:
                        sectionfilename = filebasename + "_part" + str(section)
                        sectionfilepath = os.path.join(
                            tempdir, sectionfilename)

                        sectioncompsigpath = os.path.join(
                            sigpath, sectionfilename + ".compsig"
                        )
                        sigfullpath = os.path.join(tempdir, sigpath)
                        if not os.path.exists(sigfullpath):
                            os.makedirs(sigfullpath)
                        writefile = open(sectionfilepath, "wb")
                        writefile.write(data)
                        writefile.close()

                        item = (
                            filename,
                            sectionfilepath,
                            sectioncompsigpath,
                            section - 1,
                        )

                        filelist.append(item)
                        section += 1

                    if len(data) != maxcompsize:
                        break

            return filelist
        else:
            return [(filename, options["component"], options["componentsig"], 0)]

    def componentvalidation(self, options, filestoupload):
        ret = {}
        ret["validation"] = True
        prevfile = None

        path = "/redfish/v1/UpdateService/ComponentRepository/?$expand=."
        results = self.get_request(self.root_uri + path)
        if not results['ret']:
            raise UnsuccesfulRequest(
                "Request is not completed successfully. " + str(results))
        results = results['data']

        if "Members" in results and results["Members"]:
            for comp in results["Members"]:
                for filehndl in filestoupload:
                    if (
                        comp["Filename"].upper() == str(filehndl[0]).upper()
                        and not options["forceupload"]
                        and prevfile != filehndl[0].upper()
                    ):

                        if not options["overwrite"]:
                            ret["msg"] = "Upload stopped by user due to filename conflict. \
                                If you would like to bypass this check include the --forceupload option"
                            ret["validation"] = False
                            break

                    if options["update_repository"]:
                        if (
                            comp["Filename"].upper() == str(
                                filehndl[0]).upper()
                            and prevfile != filehndl[0].upper()
                            and comp["Locked"]
                        ):
                            ret["msg"] = "Error: Component is currently locked by a taskqueue task or installset. \
                                \n Remove any installsets or taskqueue tasks containing the file and try again OR \
                                use taskqueue command to put the component to installation queue\n"
                            ret["validation"] = False
                            break
                    prevfile = str(comp["Filename"].upper())
        return ret

    def get_update_service_state(self):

        path = "/redfish/v1/UpdateService"
        results = self.get_request(self.root_uri + path)

        if results["ret"]:
            output = results["data"]
            return (output["Oem"]["Hpe"]["State"]).upper(), results["data"]
        else:
            return "UNKNOWN", {}

    def wait_for_state_change(self, wait_time=4800):

        total_time = 0
        state = ""

        while total_time < wait_time:
            state, t1 = self.get_update_service_state()

            if state == "ERROR":
                return False
            elif state != "COMPLETED" and state != "IDLE" and state != "COMPLETE":
                # Lets try again after 8 seconds
                count = 0

                # fancy spinner
                while count <= 32:
                    time.sleep(0.25)
                    count += 1

                total_time += 8
            else:
                break

        if total_time > wait_time:
            raise TimeOutError(
                "UpdateService in " + state +
                " state for " + str(wait_time) + "s"
            )

        return True

    def uploadfunction(self, filestoupload, options):

        state, result = self.get_update_service_state()
        ret = {}
        if (
            state != "COMPLETED"
            and state != "COMPLETE"
            and state != "ERROR"
            and state != "IDLE"
        ):
            ret["msg"] = "iLO UpdateService is busy. Please try again."
            ret["ret"] = False
            return ret

        etag = ""
        hpe = result["Oem"]["Hpe"]
        urltosend = "/cgi-bin/uploadFile"

        if "PushUpdateUri" in hpe:
            urltosend = hpe["PushUpdateUri"]
        elif "HttpPushUri" in result:
            urltosend = result["HttpPushUri"]
        else:
            ret["msg"] = "Failed to upload component"
            ret["ret"] = False
            return ret

        for item in filestoupload:
            ilo_upload_filename = item[0]

            ilo_upload_compsig_filename = (
                ilo_upload_filename[: ilo_upload_filename.rfind(
                    ".")] + ".compsig"
            )

            componentpath = item[1]
            compsigpath = item[2]

            t1, filename = os.path.split(componentpath)

            if not etag:
                etag = "sum" + filename.replace(".", "")
                etag = etag.replace("-", "")
                etag = etag.replace("_", "")

            section_num = item[3]

            user = self.creds['user']
            pwd = self.creds['pswd']
            baseurl = self.root_uri

            redfish_obj = redfish.RedfishClient(base_url=baseurl, username=user, password=pwd)
            redfish_obj.login()
            session_key = redfish_obj.session_key

            parameters = {
                "UpdateRepository": options["update_repository"],
                "UpdateTarget": options["update_target"],
                "ETag": etag,
                "Section": section_num,
                "UpdateRecoverySet": options["update_srs"],
            }

            data = [("sessionKey", session_key), ("parameters", json.dumps(parameters))]

            if not compsigpath:
                compsigpath = self.findcompsig(componentpath)
            if compsigpath:
                with open(compsigpath, "rb") as fle:
                    output = fle.read()
                data.append(
                    (
                        "compsig",
                        (
                            ilo_upload_compsig_filename,
                            output,
                            "application/octet-stream",
                        ),
                    )
                )
                output = None

            with open(componentpath, "rb") as fle:
                output = fle.read()

            data.append(
                ("file", (ilo_upload_filename, output, "application/octet-stream"))
            )

            headers = {'Cookie': 'sessionKey=' + session_key, 'X-Auth-Token': session_key, 'OData-Version': '4.0'}

            args = None

            results = redfish_obj.post(str(urltosend), data, args=args, headers=headers)

            if results.status == 200:
                ret["ret"] = True
                ret["msg"] = "Uploaded successfully"

            else:
                ret["msg"] = "iLO UpdateService is busy. Please try again."
                ret["ret"] = False
                return ret

            if not self.wait_for_state_change():
                raise UploadError("Error while processing the component.")

        return ret

    def human_readable_time(self, seconds):

        seconds = int(seconds)
        hours = seconds / 3600
        seconds = seconds % 3600
        minutes = seconds / 60
        seconds = seconds % 60

        return "{0} hour(s) {1} minute(s) {2} second(s) ".format(
            str(hours), str(minutes), str(seconds)
        )

    def uploadcomp(self, options):
        fwpkg = False
        result = {}
        if options["component"].endswith(".fwpkg"):
            comp, loc, ctype = self.preparefwpkg(options["component"])

        filestoupload = self.check_and_split(options)

        return_val = self.componentvalidation(options, filestoupload)

        if return_val['validation']:
            start_time = time.time()
            result["ret"] = False

            rec_res = self.uploadfunction(filestoupload, options)
            if rec_res["ret"]:
                result["ret"] = True
                result["msg"] = rec_res["msg"] + "\n"
                result["msg"] += str(self.human_readable_time(time.time() - start_time))

            if len(filestoupload) > 1:
                path, t1 = os.path.split((filestoupload[0])[1])
                shutil.rmtree(path)
            elif fwpkg:
                if os.path.exists(loc):
                    shutil.rmtree(loc)
        else:
            return_val["ret"] = False
            return return_val

        return result

    def applyfwpkg(self, options, tempdir, components, comptype):

        for component in components:
            if component.endswith(".fwpkg") or component.endswith(".zip"):
                options["component"] = component
            else:
                options["component"] = os.path.join(tempdir, component)

            if comptype in ["A", "B"]:
                options["update_target"] = True
                options["update_repository"] = True

            if options["update_srs"]:
                options["update_srs"] = True

            try:
                ret = self.uploadcomp(options)
                if not ret['ret']:
                    raise UploadError
                return ret
            except UploadError:
                if comptype in ["A", "B"]:
                    results = self.get_request(
                        self.root_uri + self.service_root + "UpdateService/")
                    if not results["ret"]:
                        raise UnsuccesfulRequest(
                            "Request is not completed successfully. " + str(results))

                    if results:
                        check = "Error occured while uploading the firmware"
                        raise UnsuccesfulRequest(check)
                    else:
                        raise FirmwareUpdateError(
                            "Error occurred while updating the firmware."
                        )
                else:
                    raise UploadError("Error uploading component.")

    def flash_firmware(self, options):
        resource = self._find_managers_resource()
        response = self.get_request(self.root_uri + self.manager_uri)
        if response['ret'] is False:
            return response

        version = float(response['data']['FirmwareVersion'][4] + "." + response['data']
                        ['FirmwareVersion'][7] + response['data']['FirmwareVersion'][9:11])

        if version <= 5.120 and options["fwpkgfile"].lower().startswith("iegen10"):
            raise IncompatibleiLOVersionError(
                "Please upgrade to iLO 5 1.20 or greater to ensure correct flash of this firmware."
            )

        if not options["fwpkgfile"].endswith(".fwpkg"):
            raise InvalidFileInputError(
                "Invalid file type. Please make sure the file provided is a valid .fwpkg file type."
            )

        result = {}
        tempdir = ""

        try:
            components, tempdir, comptype = self.preparefwpkg(
                options["fwpkgfile"])
            if comptype == "D":
                raise InvalidFileInputError("Unable to flash this fwpkg file.")

            final = self.applyfwpkg(options, tempdir, components, comptype)
            result = {}
            if final["ret"]:
                result["msg"] = final["msg"] + "\n"
                if comptype == "A":
                    result['msg'] += "Firmware has successfully been flashed. \n "
                    if "ilo" in options["fwpkgfile"].lower():
                        result['msg'] += "iLO will reboot to complete flashing. Session will be terminated."

                elif comptype == "B":
                    result['msg'] += "Firmware has successfully been flashed and a reboot is required for this firmware to take effect.\n"

                elif comptype == "C":
                    result['msg'] += "This firmware is set to flash on reboot.\n"
                result['ret'] = True
                result['changed'] = True

            else:
                result["ret"] = False
                result["msg"] = final.get("msg")

        except (FirmwareUpdateError, UploadError) as excp:
            raise excp

        finally:
            if tempdir:
                shutil.rmtree(tempdir)
        return result

    def get_network_boot_settings(self):
        # This method returns network boot settings present in the OOB controller
        result = {}

        uri = self.root_uri + self.systems_uri + "bios/"
        response = self.get_request(uri)
        if not response["ret"]:
            return response

        data = response["data"]

        if 'Oem' in data and 'Hpe' in data["Oem"] and 'Links' in data['Oem']['Hpe'] and 'Boot' in \
                data['Oem']['Hpe']['Links']:
            uri = data['Oem']['Hpe']['Links']['Boot']['@odata.id'] + "settings"
            response = self.get_request(self.root_uri + uri)
            if not response["ret"]:
                return response
            result["ret"] = True
            self.remove_odata(response)
            result["msg"] = self.remove_odata(response["data"])
        else:
            return {
                "ret": False,
                "msg": "Boot settings uri not found in %s response, %s" % (uri, data)
            }

        return result

    def get_physical_drives(self):
        # This method returns list of physical drives present in the OOB controller
        physical_drives = {}
        physical_drives_count = 0
        result = {}

        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response = self.get_request(self.root_uri + self.systems_uri + "SmartStorage/ArrayControllers/")

        if not response["ret"]:
            return response

        data = response["data"]
        if data["Members@odata.count"] == 0:
            # return physical_drives, physical_drives_count
            result["physical_drives"] = {}
            result["physical_drives_count"] = 0
            return {
                "ret": True,
                "msg": result
            }

        # Get Members of ArrayControllers
        for mem in data["Members"]:
            physical_drive_list = []
            array_url = mem["@odata.id"]
            response = self.get_request(
                self.root_uri + mem["@odata.id"]
            )

            if not response["ret"]:
                return response

            data = response["data"]
            if 'Links' in data and 'PhysicalDrives' in data['Links']:
                log_url = data['Links']['PhysicalDrives']['@odata.id']
            elif 'links' in data and 'PhysicalDrives' in data['links']:
                log_url = data['links']['PhysicalDrives']['href']
            else:
                return {
                    "ret": False,
                    "msg": "Physical drive URI not found in %s response: %s" % (mem["@odata.id"], data)
                }

            # Get list of physical drives URI
            response = self.get_request(
                self.root_uri + log_url
            )

            if not response["ret"]:
                return response

            json_data = response["data"]
            for entry in json_data["Members"]:
                # Get each physical drives details
                response = self.get_request(
                    self.root_uri + entry["@odata.id"]
                )

                if not response["ret"]:
                    return response

                log_data = self.remove_odata(response["data"])
                physical_drive_list.append(log_data)
            physical_drives.update({"array_controller_" + str(array_url.split("/")[-2]): physical_drive_list})
            physical_drives_count = physical_drives_count + len(physical_drive_list)
            result["physical_drives"] = physical_drives
            result["physical_drives_count"] = physical_drives_count

        return {
            "msg": result,
            "ret": True
        }
        # return result

    def get_logical_drives(self, array_controllers=False):
        # This method returns the logical drives details
        logical_drives_details = []
        if array_controllers:
            logical_drives = {}
            logical_drives_count = 0

        result = {}

        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        url = self.root_uri + self.systems_uri + "SmartStorage/"
        response = self.get_request(url)
        if not response["ret"]:
            return response

        json_data = response["data"]
        # Getting Array Controllers details
        if "ArrayControllers" not in json_data["Links"]:
            return {
                "ret": False,
                "msg": "Array Controllers data not found in %s response: %s" % (url, str(json_data))
            }

        response = self.get_request(
            self.root_uri + json_data["Links"]["ArrayControllers"]["@odata.id"]
        )
        if not response["ret"]:
            return response

        json_data = response["data"]

        # Getting details for each member in Array Controllers
        for entry in json_data["Members"]:
            array_url = entry["@odata.id"]
            log = self.get_request(
                self.root_uri + entry["@odata.id"]
            )
            if not response["ret"]:
                return response
            log_details = log["data"]

            # Getting logical drives details
            if "LogicalDrives" not in log_details["Links"]:
                return {
                    "ret": False,
                    "msg": "Logical Drives URI not found in %s response: %s" % (entry["@odata.id"], str(log_details))
                }

            response = self.get_request(
                self.root_uri + log_details["Links"]["LogicalDrives"]["@odata.id"]
            )
            if not response["ret"]:
                return response

            logicalDrivesData = response["data"]

            # Getting details for each member in Logical Drives
            for member in logicalDrivesData["Members"]:
                response = self.get_request(
                    self.root_uri + member["@odata.id"]
                )
                if not response["ret"]:
                    return response
                member_data = self.remove_odata(response["data"])

                # Getting data drives details
                if "DataDrives" not in member_data["Links"]:
                    return {
                        "ret": False,
                        "msg": "Physical Drives information not found in %s response: %s" % (
                            member["@odata.id"], str(member_data))
                    }

                member_data["data_drives"] = []
                response = self.get_request(
                    self.root_uri + member_data["Links"]["DataDrives"]["@odata.id"]
                )
                if not response["ret"]:
                    return response
                data_drive_res = response["data"]

                # Getting details for each member in Data Drives
                for mem in data_drive_res["Members"]:
                    response = self.get_request(
                        self.root_uri + mem["@odata.id"]
                    )
                    if not response["ret"]:
                        return response
                    data_drive_member_details = self.remove_odata(response["data"])
                    member_data["data_drives"].append(data_drive_member_details)
                logical_drives_details.append(member_data)
            if array_controllers:
                logical_drives.update({"array_controller_" + str(array_url.split("/")[-2]): logical_drives_details})
                logical_drives_count = logical_drives_count + len(logical_drives_details)
                result["logical_drives"] = logical_drives
                result["logical_drives_count"] = logical_drives_count
                # result["ret"] = True
                return {
                    "msg": result,
                    "ret": True
                }
            # return result

        result["logical_drives_details"] = logical_drives_details
        # result["ret"] = True
        return {
            "msg": result,
            "ret": True
        }
        # return result

    def remove_odata(self, output):
        # Remove odata variables given in the list
        remove_list = ["@odata.context", "@odata.etag", "@odata.id", "@odata.type"]
        for key in remove_list:
            if key in output:
                output.pop(key)
        return output

    def verify_drive_count(self, raid_details, logical_drives_count):
        if len(raid_details) != logical_drives_count:
            return {
                "ret": False,
                "changed": False,
                "msg": "Logical drive count in raid details is not matching with logical drives present in the server"
            }
        return {
            "ret": True,
            "msg": "Drive count is same as input"
        }

    def verify_logical_drives(self, raid_details, check_length=False):
        # This method verifies logical drives present in the OOB controller against the provided input
        result = self.get_logical_drives()
        if not result["ret"]:
            return result

        logical_drives_details = result["msg"]["logical_drives_details"]
        logical_drives_count = int(len(logical_drives_details))
        if check_length:
            response = self.verify_drive_count(raid_details, logical_drives_count)
            if not response["ret"]:
                return response

        not_available = []
        for raid in raid_details:
            flag = False
            for drive in logical_drives_details:
                if drive["LogicalDriveName"] == raid["LogicalDriveName"]:
                    if ("Raid" + drive["Raid"]) != raid["Raid"]:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Verification Failed! Raid type mismatch in %s" % drive["LogicalDriveName"]
                        }
                    if len(drive["data_drives"]) != raid["DataDrives"]["DataDriveCount"]:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Verification Failed! Physical drive count mismatch in %s" % drive[
                                "LogicalDriveName"]
                        }
                    if drive["MediaType"] != raid["DataDrives"]["DataDriveMediaType"]:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Verification Failed! Media Type mismatch in %s" % drive["LogicalDriveName"]
                        }
                    if drive["InterfaceType"] != raid["DataDrives"]["DataDriveInterfaceType"]:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Verification Failed! Interface Type mismatch in %s" % drive["LogicalDriveName"]
                        }
                    for data_drive in drive["data_drives"]:
                        if data_drive["CapacityGB"] < raid["DataDrives"]["DataDriveMinimumSizeGiB"]:
                            return {
                                "ret": False,
                                "changed": False,
                                "msg": "Verification Failed! Data Drive minimum size is not satisfied in %s" % drive[
                                    "LogicalDriveName"]
                            }
                    flag = True
            if not flag:
                not_available.append(raid["LogicalDriveName"])
        if not_available:
            return {
                "ret": False,
                "changed": False,
                "msg": "Verification Failed! Logical drives are not matching: %s" % not_available
            }
        else:
            return {
                "ret": True,
                "changed": False,
                "msg": "Logical drives verification completed"
            }

    def verify_uefi_boot_order(self, uefi_boot_order):
        # This method verifies UEFI boot order present in the OOB controller against the provided input
        input_boot_order = uefi_boot_order

        # response = self.get_bios_attributes()
        response = self.get_multi_bios_attributes()

        if not response["ret"]:
            return response

        if response["entries"][0][1]["BootMode"].lower() != "uefi":
            return {
                "ret": False,
                "changed": False,
                "msg": "Server Boot Mode is not UEFI. Hence Boot Order can't be verified"
            }

        response = self.get_network_boot_settings()
        if not response["ret"]:
            return response
        server_boot_order = response["msg"]["PersistentBootConfigOrder"]

        if len(server_boot_order) < len(input_boot_order):
            return {
                "ret": False,
                "changed": False,
                "msg": "Lesser number of elements in Server Boot Order %s than Input Boot Order %s" % (str(len(server_boot_order)), str(len(input_boot_order)))
            }

        for i in range(0, len(input_boot_order)):
            if input_boot_order[i].lower() != server_boot_order[i].lower():
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Input Boot Order %s doesn't match with Server Boot Order %s" % (str(input_boot_order), str(server_boot_order))
                }
        return {
            "ret": True,
            "changed": False,
            "msg": "Input Boot Order matches with the Server Boot Order"
        }

    def delete_all_logical_drives(self):
        # This function deletes all the logical drives
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response = self.get_logical_drives()
        if not response["ret"]:
            return response

        if not response["msg"]["logical_drives_details"]:
            return {
                "ret": True,
                "changed": False,
                "msg": "No logical drives present on the server"
            }

        payload = {"LogicalDrives": [], "DataGuard": "Disabled"}

        smartstorageconfig_settings_uri = self.root_uri + self.systems_uri + "smartstorageconfig/settings/"
        response = self.put_request(smartstorageconfig_settings_uri, payload)

        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "Delete logical drives request sent. System Reset required."
        }

    def get_unused_drives(self):
        # This function fetches the unconfigured drives
        unused_physical_drives = []

        # Getting smart storage details
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response = self.get_request(self.root_uri + self.systems_uri + "SmartStorage/")
        if not response["ret"]:
            return response

        json_data = response["data"]
        uri = self.systems_uri + "SmartStorage/"

        # Getting Array Controllers details
        if "ArrayControllers" not in json_data["Links"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Array Controllers data not found in %s response: %s" % (uri, str(json_data))
            }

        response = self.get_request(self.root_uri + json_data["Links"]["ArrayControllers"]["@odata.id"])

        if not response["ret"]:
            return response

        json_data = response["data"]

        # Getting details for each member in Array Controllers
        for entry in json_data["Members"]:
            log = self.get_request(self.root_uri + entry["@odata.id"])
            if not log["ret"]:
                return log

            log_details = log["data"]

            response = self.get_request(self.root_uri + log_details["Links"]["UnconfiguredDrives"]["@odata.id"])
            if not response["ret"]:
                return response

            json_data = response["data"]
            for entry in json_data["Members"]:
                # Get each physical drives details
                log = self.get_request(self.root_uri + entry["@odata.id"])
                if not log["ret"]:
                    return log

                unused_physical_drives.append(log["data"])

        return {
            "ret": True,
            "changed": False,
            "unused_physical_drives": unused_physical_drives
        }

    def validation_error(self, raid, input_list, missing_param, not_defined, drive_input, command="CreateLogicalDrives"):
        # This function returns error messages for invalid inputs passed to the
        # CreateLogicalDrives and CreateLogicalDrivesWithPArticularPhysicalDrives modules
        if command == "CreateLogicalDrives":
            if missing_param:
                msg = "Input parameters %s are missing to create logical drive. " + \
                      "Mandatory parameters are %s and in data drive details: %s"
                return {
                    "ret": False,
                    "changed": False,
                    "msg": msg % (str(missing_param), str(input_list), str(drive_input))
                }

            if set(raid.keys()) - set(input_list):
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Unsupported input parameters: %s" % str(list(set(raid.keys()) - set(input_list)))
                }

            if set(raid["DataDrives"].keys()) - set(drive_input):
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Unsupported input parameters in data drive details: %s" % str(
                        list(set(raid["DataDrives"].keys()) - set(drive_input)))
                }

            if not_defined:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Input parameters %s should not be empty" % (str(not_defined))
                }

            return {
                "ret": True,
                "changed": False,
                "msg": "Input parameters verified"
            }

        elif command == "CreateLogicalDrivesWithParticularPhysicalDrives":
            msg = "Input parameters %s are missing to create logical drive. " + \
                  "Mandatory parameters are %s "
            if missing_param:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": msg % (str(missing_param), str(input_list))
                }

            if set(raid.keys()) - set(input_list):
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Unsupported input parameters: %s" % str(list(set(raid.keys()) - set(input_list)))
                }

            if not_defined:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Input parameters %s should not be empty" % (str(not_defined))
                }

            return {
                "ret": True,
                "changed": False,
                "msg": "Input parameters verified"
            }

    def verify_input_paramters(self, raid_data, command="CreateLogicalDrives"):
        # Verifying input parameters passed to the CreateLogicalDrives and
        # CreateLogicalDrivesWithPArticularPhysicalDrives modules
        if command == "CreateLogicalDrives":
            input_list = ['LogicalDriveName', 'Raid', 'DataDrives']
            drive_input = ['DataDriveCount', 'DataDriveMediaType',
                           'DataDriveInterfaceType', 'DataDriveMinimumSizeGiB']
            for raid in raid_data:
                missing_param = []
                not_defined = []
                for input in input_list:
                    if input not in raid.keys():
                        missing_param.append(input)
                    elif not raid[input]:
                        not_defined.append(input)

                if 'DataDrives' not in raid.keys():
                    missing_param = missing_param + drive_input
                else:
                    for drive in drive_input:
                        if drive not in raid["DataDrives"]:
                            missing_param.append(drive)
                        elif drive != "DataDriveMinimumSizeGiB" and not raid["DataDrives"][drive]:
                            not_defined.append(drive)
                        elif drive == "DataDriveMinimumSizeGiB" and \
                                not raid["DataDrives"]["DataDriveMinimumSizeGiB"] and \
                                raid["DataDrives"]["DataDriveMinimumSizeGiB"] != 0:
                            not_defined.append(drive)

            return self.validation_error(raid, input_list, missing_param, not_defined, drive_input)

        elif command == "CreateLogicalDrivesWithParticularPhysicalDrives":
            input_list = ['LogicalDriveName', 'CapacityGB', 'Raid', 'DataDrives']

            for raid in raid_data:
                missing_param = []
                not_defined = []
                for input in input_list:
                    if input not in raid.keys():
                        missing_param.append(input)
                    elif not raid[input]:
                        not_defined.append(input)

            return self.validation_error(raid, input_list, missing_param, not_defined, [], command="CreateLogicalDrivesWithParticularPhysicalDrives")

    def check_physical_drives(self, raid_data, unused_physical_drives, command="CreateLogicalDrives"):
        # Checking and verifying physical drives present in the OOB controller for the
        # CreateLogicalDrives and CreateLogicalDrivesWithPArticularPhysicalDrives modules
        if command == "CreateLogicalDrives":
            raid_data = sorted(raid_data, key=lambda i: i['DataDrives']['DataDriveMinimumSizeGiB'])
            unused_physical_drives = sorted(unused_physical_drives, key=lambda i: i['CapacityGB'])
            for raid in raid_data:
                for i in range(0, int(raid["DataDrives"]["DataDriveCount"])):
                    flag = False
                    unused_drives = unused_physical_drives[:]
                    for phy in unused_physical_drives:
                        if raid["DataDrives"]["DataDriveMediaType"] == phy["MediaType"] and \
                                raid["DataDrives"]["DataDriveInterfaceType"] == phy["InterfaceType"] and \
                                int(raid["DataDrives"]["DataDriveMinimumSizeGiB"]) <= int(phy["CapacityGB"]) * 0.931323:
                            unused_drives.remove(phy)
                            flag = True
                            break
                    if not flag:
                        result = "failed"
                    else:
                        result = unused_drives

                    if str(result) == "failed":
                        msg = "Free physical drive not found with media type: %s," + \
                              " interface type: %s, and minimum capacity: %s"
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": msg % (
                                raid["DataDrives"]["DataDriveMediaType"], raid["DataDrives"]["DataDriveInterfaceType"],
                                str(raid["DataDrives"]["DataDriveMinimumSizeGiB"]))
                        }
                    unused_physical_drives = result

            return {
                "ret": True,
                "changed": False,
                "msg": "Physical drives verified"
            }

        elif command == "CreateLogicalDrivesWithParticularPhysicalDrives":
            for raid in raid_data:
                capacity = 0
                for drive in raid["DataDrives"]:
                    for unused_drive in unused_physical_drives:
                        if drive == unused_drive["Location"]:
                            capacity = capacity + unused_drive["CapacityGB"]
                if capacity < raid["CapacityGB"]:
                    return {
                        "ret": False,
                        "changed": False,
                        "msg": "The physical drives provided do not satisfy the capacity provided"
                    }

            return {
                "ret": True,
                "changed": False,
                "msg": "Physical drives verified"
            }

    def check_logical_drives(self, raid, logical_drives_details, command="CreateLogicalDrives"):
        # Checking and verifying logical drives present in the OOB controller for the CreateLogicalDrives
        # and CreateLogicalDrivesWithPArticularPhysicalDrives module
        if command == "CreateLogicalDrives":
            for drive in logical_drives_details:
                if drive["LogicalDriveName"] == raid["LogicalDriveName"]:
                    if ("Raid" + drive["Raid"]) != raid["Raid"] or \
                            len(drive["data_drives"]) != raid["DataDrives"]["DataDriveCount"] or \
                            drive["MediaType"] != raid["DataDrives"]["DataDriveMediaType"] or \
                            drive["InterfaceType"] != raid["DataDrives"]["DataDriveInterfaceType"]:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Already logical drive exists with same name: '%s', but different details" % str(
                                drive["LogicalDriveName"])
                        }

                    for data_drive in drive["data_drives"]:
                        if int(data_drive["CapacityGB"]) * 0.931323 < raid["DataDrives"]["DataDriveMinimumSizeGiB"]:
                            return {
                                "ret": False,
                                "changed": False,
                                "msg": "Already logical drive exists with same name: '%s', but different details" % str(
                                    drive["LogicalDriveName"])
                            }

                    return {
                        "ret": True,
                        "changed": False,
                        "msg": "Logical drive provided is present in server"
                    }

            return {
                "ret": False,
                "changed": False,
                "msg": "Logical drive provided is not present in server"
            }

        elif command == "CreateLogicalDrivesWithParticularPhysicalDrives":
            for drive in logical_drives_details:
                if drive["LogicalDriveName"] == raid["LogicalDriveName"]:
                    if ("Raid" + drive["Raid"]) != raid["Raid"] or \
                            len(drive["data_drives"]) != len(raid["DataDrives"]):
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Already logical drive exists with same name: '%s', but different details" % str(
                                drive["LogicalDriveName"])
                        }

                    for data_drive in drive["data_drives"]:
                        if int(data_drive["CapacityGB"]) * 0.931323 < raid["CapacityGB"]:
                            return {
                                "ret": False,
                                "changed": False,
                                "msg": "Already logical drive exists with same name: '%s', but different details" % str(
                                    drive["LogicalDriveName"])
                            }

                    return {
                        "ret": True,
                        "changed": False,
                        "msg": "Logical drive provided is present in server"
                    }

            return {
                "ret": False,
                "changed": False,
                "msg": "Logical drive provided is not present in server"
            }

    def check_physical_drive_count(self, raid_data, unused_physical_drives, command="CreateLogicalDrives"):
        # Check physical drives are available in the OOB controller to create logical drives
        if command == "CreateLogicalDrives":
            needed_phy = 0
            for ld in raid_data:
                needed_phy = needed_phy + int(ld["DataDrives"]["DataDriveCount"])

            # Check available drives
            if not unused_physical_drives:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Free Physical drives are not available in the server"
                }

            if len(unused_physical_drives) < needed_phy:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Less number of Physical drives available in the server"
                }

            return {
                "ret": True,
                "changed": False,
                "msg": "Physical drive count verified"
            }

        elif command == "CreateLogicalDrivesWithParticularPhysicalDrives":
            needed_phy_drives = [drive for ld in raid_data for drive in ld["DataDrives"]]
            needed_phy = len(needed_phy_drives)

            # Check available drives
            if not unused_physical_drives:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Free Physical drives are not available in the server"
                }

            if len(unused_physical_drives) < needed_phy:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Less number of Physical drives available in the server"
                }

            unused_physical_drives_locations = []
            for drive in unused_physical_drives:
                unused_physical_drives_locations.append(drive["Location"])

            for drive in needed_phy_drives:
                if drive not in unused_physical_drives_locations:
                    return {
                        "ret": False,
                        "changed": False,
                        "msg": "The drive %s is not free" % str(drive)
                    }

            return {
                "ret": True,
                "changed": False,
                "msg": "Physical drive count verified"
            }

    def verify_raid_details(self, raid_data):
        # Verifying raid details for CreateLogicalDrivesWithPArticularPhysicalDrives module
        data_drive_locations = []

        for raid in raid_data:
            for drive in raid["DataDrives"]:
                if drive in data_drive_locations:
                    return {
                        "ret": False,
                        "changed": False,
                        "msg": "Same Data Drive provided for multiple logical drives to be created, "
                               "a data drive can be given only once for any logical drive in raid_details"
                    }

                else:
                    data_drive_locations.append(drive)

        return {
            "ret": True,
            "changed": False,
            "msg": "RAID details verified"
        }

    def create_logical_drives(self, raid_data):
        # This function invokes the creation of logical drive.

        # verify input parameters
        response = self.verify_input_paramters(raid_data)
        if not response["ret"]:
            return response

        # Get logical drives from server
        logical_drives_details_response = self.get_logical_drives()
        if not logical_drives_details_response["ret"]:
            return logical_drives_details_response

        logical_drives_details = logical_drives_details_response["msg"]["logical_drives_details"]
        response = self.get_unused_drives()
        if not response["ret"]:
            return response

        unused_physical_drives = response["unused_physical_drives"]

        if logical_drives_details:
            raid_details = raid_data[:]
            for raid in raid_details:
                response = self.check_logical_drives(raid, logical_drives_details)
                if response["ret"]:
                    raid_data.remove(raid)
                elif not response["ret"] and response["msg"] != "Logical drive provided is not present in server":
                    return response

        if not raid_data:
            return {
                "ret": True,
                "changed": False,
                "msg": "Provided logical drives are already present in the server"
            }

        response = self.check_physical_drive_count(raid_data, unused_physical_drives)
        if not response["ret"]:
            return response

        response = self.check_physical_drives(raid_data, unused_physical_drives)
        if not response["ret"]:
            return response

        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response = self.get_request(self.root_uri + self.systems_uri + "smartstorageconfig/")
        if not response["ret"]:
            return response

        storage_data = response["data"]

        ld_names = [i["LogicalDriveName"] for i in raid_data]
        LogicalDrives = storage_data["LogicalDrives"]
        body = {"LogicalDrives": LogicalDrives + raid_data, "DataGuard": "Permissive"}
        url = "smartstorageconfig/settings/"
        res = self.put_request(self.root_uri + self.systems_uri + url, body)

        if not res["ret"]:
            return res

        return {
            "ret": True,
            "changed": True,
            "msg": "Create logical drives request sent for %s. System Reset required." % str(ld_names)
        }

    def create_logical_drives_with_particular_physical_drives(self, raid_data):
        # This function invokes the creation of logical drive with paticular physical drives

        # verify input parameters
        response = self.verify_input_paramters(raid_data, "CreateLogicalDrivesWithParticularPhysicalDrives")
        if not response["ret"]:
            return response

        response = self.verify_raid_details(raid_data)
        if not response["ret"]:
            return response

        # Get logical drives from server
        logical_drives_details_response = self.get_logical_drives()
        if not logical_drives_details_response["ret"]:
            return logical_drives_details_response

        logical_drives_details = logical_drives_details_response["msg"]["logical_drives_details"]
        response = self.get_unused_drives()
        if not response["ret"]:
            return response

        unused_physical_drives = response["unused_physical_drives"]

        if logical_drives_details:
            raid_details = raid_data[:]
            for raid in raid_details:
                response = self.check_logical_drives(raid, logical_drives_details, "CreateLogicalDrivesWithParticularPhysicalDrives")
                if response["ret"]:
                    raid_data.remove(raid)
                elif not response["ret"] and response["msg"] != "Logical drive provided is not present in server":
                    return response
        if not raid_data:
            return {
                "ret": True,
                "changed": False,
                "msg": "Provided logical drives are already present in the server"
            }

        response = self.check_physical_drive_count(raid_data, unused_physical_drives,
                                                                "CreateLogicalDrivesWithParticularPhysicalDrives")
        if not response["ret"]:
            return response

        response = self.check_physical_drives(raid_data, unused_physical_drives, "CreateLogicalDrivesWithParticularPhysicalDrives")
        if not response["ret"]:
            return response

        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response = self.get_request(self.root_uri + self.systems_uri + "smartstorageconfig/")
        if not response["ret"]:
            return response

        storage_data = response["data"]

        ld_names = [i["LogicalDriveName"] for i in raid_data]
        LogicalDrives = storage_data["LogicalDrives"]
        body = {}
        body["LogicalDrives"] = LogicalDrives + raid_data
        body["DataGuard"] = "Permissive"
        url = "smartstorageconfig/settings/"

        res = self.put_request(self.root_uri + self.systems_uri + url, body)

        if not res["ret"]:
            return res

        return {
            "ret": True,
            "changed": True,
            "msg": "Create logical drives request sent for %s. System Reset required." % str(ld_names)
        }

    def delete_specified_logical_drives(self, logical_drives_names):
        # This function makes call to Server through redfish client to delete logical drives
        # in OOB controller whose names are given in the logical_drives_names parameter

        body = {"LogicalDrives": [], "DataGuard": "Permissive"}

        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        url = self.systems_uri + "smartstorageconfig/settings/"

        logical_drives_details_response = self.get_logical_drives()
        if not logical_drives_details_response["ret"]:
            return logical_drives_details_response

        logical_drives_details = logical_drives_details_response["msg"]["logical_drives_details"]

        for name in logical_drives_names:
            flag = False
            for drive in logical_drives_details:
                if name == drive["LogicalDriveName"]:
                    body["LogicalDrives"].append({"Actions": [{"Action": "LogicalDriveDelete"}],
                                                  "VolumeUniqueIdentifier": drive["VolumeUniqueIdentifier"]})
                    flag = True
            if not flag:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "No logical drives on the server match with the given logical drive name %s" % name
                }

        res = self.put_request(self.root_uri + url, body)

        if not res["ret"]:
            return res

        return {
            "ret": True,
            "changed": True,
            "msg": "Delete logical drives request sent for %s. System Reset required." % str(logical_drives_names)
        }

    def delete_all_snmpv3_users(self):
        # This method deletes all SNMPv3 users
        server_snmpv3_users = self.get_snmpv3_users()
        if not server_snmpv3_users["ret"]:
            return server_snmpv3_users

        if not server_snmpv3_users["msg"]:
            return {
                "ret": True,
                "changed": False,
                "msg": "No SNMPv3 users present on the server"
            }

        delete_fail = []
        # Loop over list of SNMPv3 users
        for data in server_snmpv3_users["msg"]:
            # DELETE SNMPv3 user
            uri = self.root_uri + self.manager_uri + "SnmpService/SNMPUsers/"
            response = self.delete_request(uri + data["Id"])
            if not response["ret"]:
                delete_fail.append({"user": data["SecurityName"],
                                    "response": response["msg"]})
        if delete_fail:
            return {
                "ret": False,
                "msg": "Deleting SNMPv3 users failed: %s" % str(delete_fail)
            }

        return {
            "ret": True,
            "changed": True,
            "msg": "SNMPv3 users are deleted"
        }

    def delete_all_snmp_alert_destinations(self):
        # This method deletes all SNMP alert destinations
        server_alert_destinations = self.get_snmp_alert_destinations()
        if not server_alert_destinations["ret"]:
            return server_alert_destinations

        if not server_alert_destinations["msg"]:
            return {
                "ret": True,
                "changed": False,
                "msg": "No SNMP Alert Destinations present on the server"
            }

        delete_fail = []
        # Loop over list of SNMP alert destinations
        for data in server_alert_destinations["msg"]:
            # DELETE SNMP alert destination
            uri = self.root_uri + self.manager_uri + "SnmpService/SNMPAlertDestinations/"
            response = self.delete_request(uri + data["Id"])
            if not response["ret"]:
                delete_fail.append({"AlertDestination": data["AlertDestination"],
                                    "response": response["msg"]})
        if delete_fail:
            return {
                "ret": False,
                "msg": "Deleting SNMP alert destinations failed: %s" % str(delete_fail)
            }

        return {
            "ret": True,
            "changed": True,
            "msg": "SNMP Alert Destinations are deleted"
        }

    def delete_snmpv3_users(self, snmpv3_users):
        # This method deletes provided SNMPv3 users
        server_snmpv3_users = self.get_snmpv3_users()
        if not server_snmpv3_users["ret"]:
            return server_snmpv3_users
        server_snmpv3_users = server_snmpv3_users["msg"]

        snmpv3_users = list(set(snmpv3_users))
        # Validating if SNMPv3 users exists or not
        wrong_user = []
        for user in snmpv3_users:
            if user not in [data["SecurityName"] for data in server_snmpv3_users]:
                wrong_user.append(user)
        if wrong_user:
            return {
                "ret": False,
                "msg": "Provided SNMPv3 users are not present in the server: %s" % str(wrong_user)
            }

        uri = self.root_uri + self.manager_uri + "SnmpService/SNMPUsers/"
        delete_fail = []
        # Loop over list of SNMPv3 users
        for user in snmpv3_users:
            for data in server_snmpv3_users:
                if user == data["SecurityName"]:
                    # DELETE SNMPv3 user
                    response = self.delete_request(uri + data["Id"])
                    if not response["ret"]:
                        delete_fail.append({"user": user,
                                            "response": response["msg"]})
        if delete_fail:
            return {
                "ret": False,
                "msg": "Deleting SNMPv3 users failed: %s" % str(delete_fail)
            }

        return {
            "ret": True,
            "changed": True,
            "msg": "SNMPv3 users are deleted"
        }

    def get_specified_logical_drives(self, logical_drives_names):
        # This method returns logical drives details for provided logical drive names
        result = {}
        logical_drives_names_list = logical_drives_names[:]
        response = self.get_logical_drives()
        if not response["ret"]:
            return response

        logical_drives_details = response["msg"]["logical_drives_details"]

        needed_logical_drives = []

        for drive in logical_drives_details:
            for drive_name in logical_drives_names:
                if drive_name == drive["LogicalDriveName"]:
                    needed_logical_drives.append(drive)
                    logical_drives_names_list.remove(drive_name)

        if logical_drives_names_list:
            return {
                "ret": False,
                "msg": "Logical drives with these names were not found on the server: %s " % str(logical_drives_names_list)
            }

        result["logical_drives_details"] = needed_logical_drives

        return {
            "ret": True,
            "msg": result
        }

    def validate_engine_id(self, user):
        # Validating user Engine ID

        error_msg = "Provided invalid engine ID: '%s'. " \
                    "User Engine ID must be a hexadecimal string" \
                    " with an even number of 10 to 64 characters, " \
                    "excluding the first two characters, " \
                    "0x (for example, 0x0123456789abcdef)"

        if not user['user_engine_id']:
            return {
                "ret": False,
                "msg": error_msg % (str(user['user_engine_id']))
            }

        engine_id = user['user_engine_id']
        if (len(engine_id) < 12 or len(engine_id) > 66) or \
                (not engine_id.startswith("0x")) or \
                (len(engine_id[2:]) % 2 != 0):
            return {
                "ret": False,
                "msg": error_msg % (user['user_engine_id'])
            }
        for id in engine_id[2:]:
            if id.lower() not in set("0123456789abcdef"):
                return {
                    "ret": False,
                    "msg": error_msg % (user['user_engine_id'])
                }
        return {"ret": True}

    def validate_snmpv3user_value(self, user, module):
        # SNMP user value validation
        allowed_list = ['security_name', 'auth_protocol', 'auth_passphrase',
                        'privacy_protocol', 'privacy_passphrase',
                        'user_engine_id']
        validate_dict = {"auth_protocol": ["MD5", "SHA", "SHA256"],
                         "privacy_protocol": ["DES", "AES"]}
        if "security_name" not in user:
            return {
                "ret": False,
                "msg": "Input parameter 'security_name' is missing"
            }
        if not user["security_name"]:
            return {
                "ret": False,
                "msg": "'security_name' value should not be empty"
            }
        if module == "update" and len(user) == 1:
            err_msg = "Provide a minimum of one input parameter for SNMPv3 user: %s. Allowed parameters are: %s"
            return {
                "ret": False,
                "msg": err_msg % (str(user["security_name"]), allowed_list[1:])
            }
        for key, value in validate_dict.items():
            if key in user and user[key] not in value:
                return {
                    "ret": False,
                    "msg": "Given value '%s' is not supported for '%s'" % (user[key], key)
                }

        if not user["auth_passphrase"]:
            return {
                "ret": False,
                "msg": "auth_passphrase value cannot be empty"
            }

        if not user["privacy_passphrase"]:
            return {
                "ret": False,
                "msg": "privacy_passphrase value cannot be empty"
            }

        if ("privacy_passphrase" in user and not len(user["privacy_passphrase"]) >= 8) or \
                ("auth_passphrase" in user and not len(user["auth_passphrase"]) >= 8):
            return {
                "ret": False,
                "msg": "Minimum character length for privacy_passphrase or auth_passphrase is 8"
            }
        if set(user.keys()) - set(allowed_list):
            return {
                "ret": False,
                "msg": "Unsupported input parameters: %s" % str(list(set(user.keys()) - set(allowed_list)))
            }
        return {"ret": True}

    def validate_snmpv3_users_input(self, server_snmpv3_users, snmpv3_users, module):
        # Validating input parameters
        if module == "create" and len(server_snmpv3_users) + len(snmpv3_users) > 8:
            message = "Maximum of 8 SNMPv3 users can be added to a server..." + \
                      "Already server has %s users and provided %s more users"
            return {
                "ret": False,
                "msg": message % (len(server_snmpv3_users), len(snmpv3_users))
            }

        input_list = ['security_name', 'auth_protocol', 'auth_passphrase',
                      'privacy_protocol', 'privacy_passphrase']

        for user in snmpv3_users:
            if module == "create":
                missing_param = [i for i in input_list if i not in user]
                if missing_param:
                    msg = "Input parameter %s is missing to create SNMPv3 user. Mandatory parameters are %s"
                    return {
                        "ret": False,
                        "msg": msg % (str(missing_param), str(input_list))
                    }
            response = self.validate_snmpv3user_value(user, module)
            if not response["ret"]:
                return response

            if 'user_engine_id' in user.keys():
                response = self.validate_engine_id(user)
                if not response["ret"]:
                    return response
        return {"ret": True}

    def check_if_snmpv3user_exists(self, server_snmpv3_users, snmpv3_users):
        # Validating if SNMPv3 users already exists
        existing_user = []
        wrong_user = []
        for user in snmpv3_users:
            flag = False
            for data in server_snmpv3_users:
                if data["SecurityName"] == user["security_name"]:
                    existing_user.append(data["SecurityName"])
                    flag = True
            if not flag:
                wrong_user.append(user["security_name"])
        return existing_user, wrong_user

    def validate_duplicate_entries(self, snmpv3_users):
        # Validating duplicate entry
        duplicate = []
        snmpv3_user_names = [i["security_name"] for i in snmpv3_users]
        for snmp in snmpv3_user_names:
            if snmpv3_user_names.count(snmp) > 1:
                duplicate.append(snmp)
        if duplicate:
            return {
                "ret": False,
                "msg": "Duplicate entries provided for users: %s" % str(list(set(duplicate)))
            }
        return {"ret": True}

    def validate_snmpv3_users(self, server_snmpv3_users, snmpv3_users, module):
        # Validating input parameters
        input_result = self.validate_snmpv3_users_input(server_snmpv3_users, snmpv3_users, module)
        if not input_result["ret"]:
            return input_result

        # Validating duplicate entry
        duplicate_entry_result = self.validate_duplicate_entries(snmpv3_users)
        if not duplicate_entry_result["ret"]:
            return duplicate_entry_result

        # Checking if user already exists
        response = self.check_if_snmpv3user_exists(server_snmpv3_users, snmpv3_users)
        if module == "create" and response[0]:
            message = "Already user exists with same name: %s"
            return {
                "ret": False,
                "msg": message % (str(response[0]))
            }
        if module == "update" and response[1]:
            return {
                "ret": False,
                "msg": "Provided SNMPv3 users are not present in the server: %s" % str(response[1])
            }
        return {"ret": True}

    def update_snmpv3_users(self, snmpv3_users):
        # This method updates SNMPv3 users with provided input
        server_snmpv3_users = self.get_snmpv3_users()
        if not server_snmpv3_users["ret"]:
            return server_snmpv3_users
        server_snmpv3_users = server_snmpv3_users["msg"]

        # Validating input
        validate_result = self.validate_snmpv3_users(server_snmpv3_users, snmpv3_users, "update")
        if not validate_result["ret"]:
            return validate_result

        uri = self.root_uri + self.manager_uri + "SnmpService/SNMPUsers/"
        for user in snmpv3_users:
            # Define payload
            body = {
                "SecurityName": user['security_name']
            }
            if "auth_protocol" in user:
                body["AuthProtocol"] = user['auth_protocol']
            if "auth_passphrase" in user:
                body["AuthPassphrase"] = user['auth_passphrase']
            if "privacy_protocol" in user:
                body["PrivacyProtocol"] = user['privacy_protocol']
            if "privacy_passphrase" in user:
                body["PrivacyPassphrase"] = user['privacy_passphrase']
            if 'user_engine_id' in user:
                body["UserEngineID"] = user['user_engine_id']

            # Get snmpv3 user uri
            for snmp in server_snmpv3_users:
                if user['security_name'] == snmp["SecurityName"]:
                    snmp_id = snmp["Id"]
                    break
            # PATCH on Managers API
            snmp_res = self.patch_request(uri + snmp_id, body)
            if not snmp_res["ret"]:
                return {
                    "ret": False,
                    "msg": snmp_res
                }

        return {"ret": True, "changed": True, "msg": "SNMPv3 users are updated"}

    def create_snmpv3_users(self, snmpv3_users):
        # This method creates SNMPv3 users
        server_snmpv3_users = self.get_snmpv3_users()
        if not server_snmpv3_users["ret"]:
            return server_snmpv3_users
        server_snmpv3_users = server_snmpv3_users["msg"]

        # Validating SNMPv3 users input
        validate_result = self.validate_snmpv3_users(server_snmpv3_users, snmpv3_users, "create")
        if not validate_result["ret"]:
            return validate_result

        for user in snmpv3_users:
            # Define payload
            body = {
                "SecurityName": user['security_name'],
                "AuthProtocol": user['auth_protocol'],
                "AuthPassphrase": user['auth_passphrase'],
                "PrivacyProtocol": user['privacy_protocol'],
                "PrivacyPassphrase": user['privacy_passphrase']
            }
            # Add engine ID if provided
            if 'user_engine_id' in user.keys():
                body["UserEngineID"] = user['user_engine_id']
            # POST on Managers API
            uri = self.root_uri + self.manager_uri + "SnmpService/SNMPUsers/"
            snmp_res = self.post_request(uri, body)
            if not snmp_res["ret"]:
                return {
                    "ret": False,
                    "msg": snmp_res
                }

        return {"ret": True, "changed": True, "msg": "SNMPv3 users are added"}

    def check_snmpv3_username(self, dest):
        if "security_name" not in dest or not dest["security_name"]:
            return {
                "ret": False,
                "msg": "security_name is missing for SNMP Alert protocol: '%s', destination IP: '%s'" % (
                    dest['snmp_alert_protocol'], dest["alert_destination"])
            }

        # Get existing SNMPv3 users from server
        server_snmpv3_users = self.get_snmpv3_users()
        if not server_snmpv3_users["ret"]:
            return server_snmpv3_users
        server_snmpv3_users = server_snmpv3_users["msg"]

        if dest["security_name"] not in [x["SecurityName"] for x in server_snmpv3_users]:
            return {
                "ret": False,
                "msg": "security_name '%s' does not exists, destination IP: '%s'" % (
                    dest['security_name'], dest["alert_destination"])
            }

        return {"ret": True}

    def validate_alert_destinations(self, server_alert_destinations, alert_destinations):
        # Validating input parameters for SNMP alert destinations
        if len(server_alert_destinations) + len(alert_destinations) > 8:
            message = "Maximum of 8 alert destinations can be added to a server..." + \
                      "Already server has %s Alert destinations and provided %s more Alert destinations"
            return {
                "ret": False,
                "msg": message % (len(server_alert_destinations), len(alert_destinations))
            }
        input_list = ['alert_destination', 'snmp_alert_protocol']
        allowed_list = ['alert_destination', 'snmp_alert_protocol', 'trap_community', 'security_name']
        for dest in alert_destinations:
            for input in input_list:
                if input not in dest.keys():
                    return {
                        "ret": False,
                        "msg": "Input parameter '%s' is missing to create alert destination" % input
                    }
            for input in dest.keys():
                if input not in allowed_list:
                    return {
                        "ret": False,
                        "msg": "Unsupported parameter '%s' is provided to create alert destination" % input
                    }

            if not dest["alert_destination"]:
                return {
                    "ret": False,
                    "msg": "Invalid IP address/HostName/FQDN: %s" % dest["alert_destination"]
                }

            if not isinstance(dest["alert_destination"], str):
                return {
                    "ret": False,
                    "msg": "Alert Destination should be of type 'str'"
                }

            temp = str(dest["alert_destination"]).split(".")
            if len(temp) == 4:
                try:
                    ipaddress.ip_address(dest["alert_destination"])
                except Exception as e:
                    return {
                        "ret": False,
                        "msg": "Invalid IP address: %s" % dest["alert_destination"]
                    }
            else:
                if len(str(dest["alert_destination"])) > 255:
                    return {
                        "ret": False,
                        "msg": "Invalid HostName/FQDN: %s" % dest["alert_destination"]
                    }
                if str(dest["alert_destination"])[-1] == ".":
                    hostname = str(dest["alert_destination"])[:-1]
                else:
                    hostname = str(dest["alert_destination"])

                allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
                if not all(allowed.match(x) for x in hostname.split(".")):
                    return {
                        "ret": False,
                        "msg": "Invalid HostName/FQDN: %s" % dest["alert_destination"]
                    }

            if dest['snmp_alert_protocol'].lower() == "snmpv1trap":
                dest['snmp_alert_protocol'] = "SNMPv1Trap"
            elif dest['snmp_alert_protocol'].lower() == "snmpv3trap":
                dest['snmp_alert_protocol'] = "SNMPv3Trap"
            elif dest['snmp_alert_protocol'].lower() == "snmpv3inform":
                dest['snmp_alert_protocol'] = "SNMPv3Inform"
            else:
                return {
                    "ret": False,
                    "msg": "Wrong SNMP Alert protocol '%s' is provided" % dest['snmp_alert_protocol']
                }
            if "trap_community" not in dest or not dest["trap_community"] or dest["trap_community"].lower() in ["na", " "]:
                dest["trap_community"] = ""
            if dest['snmp_alert_protocol'] in ["SNMPv1Trap"]:
                if "security_name" in dest:
                    return {
                        "ret": False,
                        "msg": "security_name is not supported for SNMP Alert protocol: '%s', destination IP: '%s'" % (
                            dest['snmp_alert_protocol'], dest["alert_destination"])
                    }
            if dest['snmp_alert_protocol'] in ["SNMPv3Trap", "SNMPv3Inform"]:
                response = self.check_snmpv3_username(dest)
                if not response["ret"]:
                    return response
        return {
            "ret": True,
            "msg": alert_destinations
        }

    def create_alert_destinations(self, alert_destinations):
        # This method creates SNMP alert destinations
        server_alert_destinations = self.get_snmp_alert_destinations()
        if not server_alert_destinations["ret"]:
            return server_alert_destinations
        server_alert_destinations = server_alert_destinations["msg"]

        # Validating alert destination input
        alert_destinations = self.validate_alert_destinations(server_alert_destinations, alert_destinations)
        if not alert_destinations["ret"]:
            return alert_destinations
        alert_destinations = alert_destinations["msg"]

        for dest in alert_destinations:
            # Define payload
            body = {
                "AlertDestination": str(dest["alert_destination"]),
                "SNMPAlertProtocol": dest['snmp_alert_protocol'],
                "TrapCommunity": dest["trap_community"]
            }
            # Adding SNMP username to Payload for SNMPv3Trap/SNMPv3Inform
            if dest['snmp_alert_protocol'] in ["SNMPv3Trap", "SNMPv3Inform"]:
                body["SecurityName"] = dest["security_name"]
            # POST on Managers API
            uri = self.root_uri + self.manager_uri + "SnmpService/SNMPAlertDestinations/"

            snmp_res = self.post_request(uri, body)
            if not snmp_res["ret"]:
                return {"ret": False, "msg": snmp_res}
        return {
            "ret": True,
            "changed": True,
            "msg": "SNMP Alert Destinations are added"
        }

    def get_server_poststate(self):
        # Get server details
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response
        server_data = response["data"]

        if "Hpe" in server_data["Oem"]:
            return {
                "ret": True,
                "server_poststate": server_data["Oem"]["Hpe"]["PostState"]
            }
        else:
            return {
                "ret": True,
                "server_poststate": server_data["Oem"]["Hp"]["PostState"]
            }

    def get_snmpv3_users(self):
        # This method returns list of SNMPv3 users
        snmpv3_users = []
        properties = ["AuthProtocol", "Id", "PrivacyProtocol", "SecurityName", "UserEngineID"]

        response = self.get_request(self.root_uri + self.manager_uri)
        if not response["ret"]:
            return response

        # Get a list of all SNMPv3 Users and build respective URIs
        response = self.get_request(self.root_uri + self.manager_uri + "SnmpService/SNMPUsers/")
        if not response["ret"]:
            return response
        snmp_list = response["data"]

        for item in snmp_list["Members"]:
            item_response = self.get_request(self.root_uri + item["@odata.id"])
            if not item_response["ret"]:
                return item_response
            data = item_response["data"]

            snmpv3_user = {}
            for property in properties:
                if property in data:
                    snmpv3_user[property] = data[property]

            snmpv3_users.append(snmpv3_user)

        return {
            "ret": True,
            "msg": snmpv3_users
        }

    def get_snmp_alert_destinations(self):
        # This method returns list of SNMP alert destinations
        alert_destinations = []
        properties = ["AlertDestination", "Id", "SNMPAlertProtocol", "SNMPv3User", "SecurityName", "TrapCommunity"]
        snmpv3_user_properties = ["AuthProtocol", "Id", "PrivacyProtocol", "SecurityName", "UserEngineID"]

        response = self.get_request(self.root_uri + self.manager_uri)
        if not response["ret"]:
            return response

        # Get a list of all SNMP ALert Destinations and build respective URIs
        response = self.get_request(self.root_uri + self.manager_uri + "SnmpService/SNMPAlertDestinations/")
        if not response["ret"]:
            return response
        snmp_list = response["data"]

        for item in snmp_list["Members"]:
            item_response = self.get_request(self.root_uri + item["@odata.id"])
            if not item_response["ret"]:
                return item_response
            data = item_response["data"]

            alert_destination = {}
            for property in properties:
                if property in data:
                    alert_destination[property] = data[property]

            if "SNMPv3User" in alert_destination:
                response = self.get_request(self.root_uri + alert_destination["SNMPv3User"]["@odata.id"])
                if not response["ret"]:
                    return response
                data = response["data"]

                snmpv3_user = {}
                for property in snmpv3_user_properties:
                    if property in data:
                        snmpv3_user[property] = data[property]

                alert_destination["SNMPv3User"] = snmpv3_user

            alert_destinations.append(alert_destination)

        return {
            "ret": True,
            "msg": alert_destinations
        }

    def wait_for_ilo_reboot_completion(self, polling_interval=60, max_polling_time=1800):
        # This method checks if OOB controller reboot is completed
        time.sleep(10)

        # Check server poststate
        state = self.get_server_poststate()
        if not state["ret"]:
            return state

        count = int(max_polling_time / polling_interval)
        times = 0

        # When server is powered OFF
        pcount = 0
        while state["server_poststate"] in ["PowerOff", "Off"] and pcount < 5:
            time.sleep(10)
            state = self.get_server_poststate()
            if not state["ret"]:
                return state

            if state["server_poststate"] not in ["PowerOff", "Off"]:
                break
            pcount = pcount + 1
        if state["server_poststate"] in ["PowerOff", "Off"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Server is powered OFF"
            }

        # When server is not rebooting
        if state["server_poststate"] in ["InPostDiscoveryComplete", "FinishedPost"]:
            return {
                "ret": True,
                "changed": False,
                "msg": "Server is not rebooting"
            }

        while state["server_poststate"] not in ["InPostDiscoveryComplete", "FinishedPost"] and count > times:
            state = self.get_server_poststate()
            if not state["ret"]:
                return state

            if state["server_poststate"] in ["InPostDiscoveryComplete", "FinishedPost"]:
                return {
                    "ret": True,
                    "changed": True,
                    "msg": "Server reboot is completed"
                }
            time.sleep(polling_interval)
            times = times + 1

        return {
            "ret": False,
            "changed": False,
            "msg": "Server Reboot has failed, server state: {state} ".format(state=state)
        }

    def set_cold_boot(self):
        # GET to systems_data
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        json_data = response["data"]

        if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or "Actions" \
            not in json_data["Oem"]["Hpe"] or "#HpeComputerSystemExt.SystemReset" \
            not in json_data["Oem"]["Hpe"]["Actions"] or "target" not in \
                json_data["Oem"]["Hpe"]["Actions"]["#HpeComputerSystemExt.SystemReset"]:
            return {
                "ret": False,
                "msg": "Coldboot URI not found in the response %s" % (json_data)
            }

        cold_boot_url = json_data["Oem"]["Hpe"]["Actions"]["#HpeComputerSystemExt.SystemReset"]["target"]

        # define payload
        payload = {
             "ResetType": "ColdBoot"
        }

        # POST to Action URI
        post_resp = self.post_request(self.root_uri + cold_boot_url, payload)

        if not post_resp["ret"]:
            return post_resp

        return {
            "ret": True,
            "changed": True,
            "msg": "ColdBoot action was successful"
        }

    def factory_reset(self):
        # Get on self.root_uri + self.service_root + /Managers/1
        response = self.get_request(self.root_uri + self.manager_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]
        if "Oem" not in response_data or "Hpe" not in response_data["Oem"] or "Actions" \
                not in response_data["Oem"]["Hpe"] or "#HpeiLO.ResetToFactoryDefaults" not in \
                response_data["Oem"]["Hpe"]["Actions"] or "target" not in \
                response_data["Oem"]["Hpe"]["Actions"]["#HpeiLO.ResetToFactoryDefaults"]:
            return {
                "ret": False,
                "msg": "Factory reset url not found in response, %s" % (response_data)
            }

        factory_reset_uri = response_data["Oem"]["Hpe"]["Actions"]["#HpeiLO.ResetToFactoryDefaults"]["target"]

        # post on self.root_uri + self.service_root + /Managers/1- + /Actions/Oem/Hpe/HpeiLO.ResetToFactoryDefaults/
        factory_reset_body = {"ResetType": "Default"}
        response = self.post_request(self.root_uri + factory_reset_uri, factory_reset_body)

        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "Factory Reset successful"
        }

    def get_ilo_backupfiles(self):
        # Get on self.root_uri + self.service_root + /Managers/1
        response = self.get_request(self.root_uri + self.manager_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "Oem" not in response_data or "Hpe" not in response_data["Oem"] or "Links" not in \
                response_data["Oem"]["Hpe"] or "BackupRestoreService" not in response_data["Oem"]["Hpe"]["Links"] \
                or "@odata.id" not in response_data["Oem"]["Hpe"]["Links"]["BackupRestoreService"]:
            return {
                "ret": False,
                "msg": "Backup url not found in response, %s" % (response_data)
            }

        backup_uri = response_data["Oem"]["Hpe"]["Links"]["BackupRestoreService"]["@odata.id"]

        # Get on self.root_uri + self.service_root + /Managers/1 + /BackupRestoreService/
        response = self.get_request(self.root_uri + backup_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "BackupFiles" not in response_data or "@odata.id" not in response_data["BackupFiles"]:
            return {
                "ret": False,
                "msg": "Backup file url not found in response, %s" % (response_data)
            }

        backup_files_url = response_data["BackupFiles"]["@odata.id"]

        # Get on self.root_uri + self.service_root + /Managers/1 + /BackupRestoreService/ + /BackupFiles/
        response = self.get_request(self.root_uri + backup_files_url)
        if not response["ret"]:
            return response

        backup_files_info_list = []

        if "Members" not in response["data"]:
            return {
                "ret": False,
                "msg": "'Members' not found in backup files url response, %s" % (response["data"])
            }

        for member in response["data"]["Members"]:
            res = self.get_request(self.root_uri + member["@odata.id"])
            if not res["ret"]:
                return res
            backup_files_info_list.append(res["data"])

        response["data"]["Members"] = backup_files_info_list

        return {
            "ret": True,
            "changed": False,
            "msg": response["data"]
        }

    def delete_ilo_backupfiles(self):
        response = self.get_ilo_backupfiles()

        if not response["ret"]:
            return response

        if "msg" not in response or "Members" not in response["msg"]:
            return {
                "ret": False,
                "msg": "Delete Backup file url not found in response, %s" % (response)
            }

        members = response["msg"]["Members"]

        # Check if backup file present on the server or not
        if len(members) == 0:
            return {
                "ret": True,
                "changed": False,
                "msg": "No backup file(s) found to delete"
            }

        for each_member in members:
            delete_res = self.delete_request(self.root_uri + each_member["@odata.id"])
            if not delete_res["ret"]:
                return delete_res

        return {
            "ret": True,
            "changed": True,
            "msg": "Deletion of backup file(s) successful"
        }

    def ilo_backup(self):
        # Get on self.root_uri + self.service_root + /Managers/1
        response = self.get_request(self.root_uri + self.manager_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "Oem" not in response_data or "Hpe" not in response_data["Oem"] or "Links" not in \
                response_data["Oem"]["Hpe"] or "BackupRestoreService" not in response_data["Oem"]["Hpe"]["Links"] \
                or "@odata.id" not in response_data["Oem"]["Hpe"]["Links"]["BackupRestoreService"]:
            return {
                "ret": False,
                "msg": "Backup url not found in response, %s" % (response_data)
            }

        backup_uri = response_data['Oem']["Hpe"]["Links"]["BackupRestoreService"]["@odata.id"]
        # Get on self.root_uri + self.service_root + /Managers/1 + /BackupRestoreService/
        response = self.get_request(self.root_uri + backup_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "BackupFiles" not in response_data or "@odata.id" not in response_data["BackupFiles"]:
            return {
                "ret": False,
                "msg": "Backup file url not found in response, %s" % (response_data)
            }

        backup_files_url = response_data["BackupFiles"]["@odata.id"]
        backup_body = {}

        # Post on self.root_uri + self.service_root + /Managers/1 + /BackupRestoreService/ + /BackupFiles/
        response = self.post_request(self.root_uri + backup_files_url, backup_body)
        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "iLO backup is successful"
        }

    def ilo_restore(self):
        # Get on self.root_uri + self.service_root + /Managers/1
        response = self.get_request(self.root_uri + self.manager_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "Oem" not in response_data or "Hpe" not in response_data["Oem"] or "Links" \
                not in response_data["Oem"]["Hpe"] or "BackupRestoreService" not in \
                response_data["Oem"]["Hpe"]["Links"] or "@odata.id" \
                not in response_data["Oem"]["Hpe"]["Links"]["BackupRestoreService"]:
            return {
                "ret": False,
                "msg": "Backup url not found in response, %s" % (response_data)
            }

        backup_uri = response_data["Oem"]["Hpe"]["Links"]["BackupRestoreService"]["@odata.id"]
        # Get on self.root_uri + self.service_root + /Managers/1 + /BackupRestoreService/
        response = self.get_request(self.root_uri + backup_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "BackupFiles" not in response_data or "@odata.id" not in response_data["BackupFiles"]:
            return {
                "ret": False,
                "msg": "Backup file url not found in response, %s" % (response_data)
            }

        backup_files_url = response_data["BackupFiles"]["@odata.id"]
        # Get on self.root_uri + self.service_root + /Managers/1 + /BackupRestoreService/ + /BackupFiles/
        response = self.get_request(self.root_uri + backup_files_url)
        if not response["ret"]:
            return response

        response_data = response["data"]
        # Check backup file present on the iLO to restore
        if response_data["Members@odata.count"] == 0:
            return {
                "ret": False,
                "changed": False,
                "msg": "No backup file found in the iLO server to restore"
            }

        if "Members" not in response_data or "@odata.id" not in response_data["Members"][0]:
            return {
                "ret": False,
                "msg": "Backup file member url not found in response, %s" % (response_data)
            }

        backup_file_member_url = response_data["Members"][0]["@odata.id"]
        # Get on self.root_uri + self.service_root + /Managers/1 + /BackupRestoreService/ + /BackupFiles/1/
        response = self.get_request(self.root_uri + backup_file_member_url)
        if not response["ret"]:
            return response

        response_data = response["data"]

        restore_body = {}

        if "Actions" not in response_data or "#HpeiLOBackupFile.Restore" not in response_data["Actions"] \
                or "target" not in response_data["Actions"]["#HpeiLOBackupFile.Restore"]:
            return {
                "ret": False,
                "msg": "Restore url not found in the response, %s" %(response_data)
            }

        restore_url = response_data["Actions"]["#HpeiLOBackupFile.Restore"]["target"]
        # Post on self.root_uri + self.service_root + /Managers/1 + BackupRestoreService/ + /BackupFiles/1/+
        # /Actions/HpeiLOBackupFile.Restore/
        response = self.post_request(self.root_uri + restore_url, restore_body)

        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "iLO restore is successful"
        }

    def get_usb_info(self):
        # Get on self.root_uri + self.service_root + /systems/1
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        usb = []

        if "Oem" not in response_data or "Hpe" not in response_data["Oem"] or "Links" not in response_data["Oem"][
            "Hpe"] \
                or "USBDevices" not in response_data["Oem"]["Hpe"]["Links"] or "@odata.id" not in \
                response_data["Oem"]["Hpe"]["Links"]["USBDevices"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "USB devices url not found in response, %s" % (response_data)
            }

        usb_member_url = response_data["Oem"]["Hpe"]["Links"]["USBDevices"]["@odata.id"]
        # Get on self.root_uri + self.service_root + /systems/1 + /USBDevices/
        usb_rsp = self.get_request(self.root_uri + usb_member_url)
        if not usb_rsp["ret"]:
            return usb_rsp

        usb_rsp_data = usb_rsp["data"]

        if "Members" not in usb_rsp_data:
            return {
                "ret": False,
                "changed": False,
                "msg": "'Members' not found in USB devices response, %s" % (usb_rsp_data)
            }

        for item in usb_rsp_data["Members"]:
            if "@odata.id" not in item:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "'@odata.id' not found in USB devices response, %s" % (usb_rsp_data)
                }
            # Get on all urls present inside members eg: self.root_uri + self.service_root + /systems/1 + /USBDevices/
            # + /Members/1
            item_rsp = self.get_request(self.root_uri + item["@odata.id"])

            if not item_rsp["ret"]:
                return item_rsp
            # storing the result in a list
            usb.append(item_rsp["data"])

        return {
            "ret": True,
            "changed": False,
            "msg": usb
        }

    def get_pcidevices_info(self):
        # Get on self.root_uri + self.service_root + /systems/1
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "Oem" not in response_data or "Hpe" not in response_data["Oem"] or "Links" not in response_data["Oem"][
            "Hpe"] \
                or "PCIDevices" not in response_data["Oem"]["Hpe"]["Links"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "PCI devices url not found in response, %s" % (response_data)
            }

        if isinstance(response_data["Oem"]["Hpe"]["Links"]["PCIDevices"], list):
            if "@odata.id" not in response_data["Oem"]["Hpe"]["Links"]["PCIDevices"][0]:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "PCI devices url not found in response, %s" % (response_data)
                }
        else:
            if "@odata.id" not in response_data["Oem"]["Hpe"]["Links"]["PCIDevices"]:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "PCI devices url not found in response, %s" % (response_data)
                }

        if isinstance(response_data["Oem"]["Hpe"]["Links"]["PCIDevices"], list):
            pci_member_url = response_data["Oem"]["Hpe"]["Links"]["PCIDevices"][0]["@odata.id"]
        else:
            pci_member_url = response_data["Oem"]["Hpe"]["Links"]["PCIDevices"]["@odata.id"]
        pci = []
        # Get on self.root_uri + self.service_root + /systems/1 + /PCIDevices/
        rsp = self.get_request(self.root_uri + pci_member_url)
        if not rsp["ret"]:
            return rsp

        pci_rsp_data = rsp["data"]

        if "Members" not in pci_rsp_data:
            return {
                "ret": False,
                "changed": False,
                "msg": "'Members' not found in PCI devices response, %s" % (pci_rsp_data)
            }

        for item in pci_rsp_data["Members"]:
            if "@odata.id" not in item:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "'@odata.id' not found in PCI devices response, %s" % (pci_rsp_data)
                }
            # Get on all urls present inside members eg: self.root_uri + self.service_root + /systems/1 + /PCIDevices/
            # + /Members/1
            item_rsp = self.get_request(self.root_uri + item["@odata.id"])
            if not item_rsp["ret"]:
                return item_rsp
            # storing the result in a list
            pci.append(item_rsp["data"])

        return {
            "ret": True,
            "changed": False,
            "msg": pci
        }

    def get_pcislots_info(self):
        # Get on self.root_uri + self.service_root + /systems/1
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        response_data = response["data"]

        if "Oem" not in response_data or "Hpe" not in response_data["Oem"] or "Links" not in response_data["Oem"][
            "Hpe"] \
                or "PCISlots" not in response_data["Oem"]["Hpe"]["Links"] or "@odata.id" not in \
                response_data["Oem"]["Hpe"]["Links"]["PCISlots"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "PCI slots url not found in response, %s" % (response_data)
            }

        pci_slots_member_url = response_data["Oem"]["Hpe"]["Links"]["PCISlots"]["@odata.id"]

        pcislots = []
        # Get on self.root_uri + self.service_root + /systems/1 + /PCISlots/
        rsp = self.get_request(self.root_uri + pci_slots_member_url)
        if not rsp["ret"]:
            return rsp

        pci_slots_rsp_data = rsp["data"]

        if "Members" not in pci_slots_rsp_data:
            return {
                "ret": False,
                "changed": False,
                "msg": "'Members' not found in PCI slots response, %s" % (pci_slots_rsp_data)
            }

        for item in pci_slots_rsp_data["Members"]:
            if "@odata.id" not in item:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "'@odata.id' not found in PCI slots response, %s" % (pci_slots_rsp_data)
                }
            # Get on all urls present inside members eg: self.root_uri + self.service_root + /systems/1 + /PCISlots/ +
            # /Members/1
            item_rsp = self.get_request(self.root_uri + item["@odata.id"])
            if not item_rsp["ret"]:
                return item_rsp
            # storing the result in a list
            pcislots.append(item_rsp["data"])

        return {
            "ret": True,
            "changed": False,
            "msg": pcislots
        }

    def get_phy_nic_info(self):
        
        # Get on self.root_uri + self.service_root + /systems/1
        response = self.get_systems_data()

        if not response["ret"]:
            return response

        json_data = response["msg"]["data"]
        # check whether gen11 server or not
        if "Gen11" not in json_data["Model"]:
            nic = []

            if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or "Links" not in json_data["Oem"]["Hpe"] \
                    or "NetworkAdapters" not in json_data["Oem"]["Hpe"]["Links"] or "@odata.id" not in \
                    json_data["Oem"]["Hpe"]["Links"]["NetworkAdapters"]:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Network Adapters url not found in response, %s" % (json_data)
                }

            OemHpdict = json_data["Oem"]["Hpe"]["Links"]["NetworkAdapters"]["@odata.id"]

            # Get on self.root_uri + self.service_root + /systems/1 + /BaseNetworkAdapters/
            ethernet_rsp = self.get_request(self.root_uri + OemHpdict)
            if not ethernet_rsp["ret"]:
                return ethernet_rsp

            ethernet_data = ethernet_rsp["data"]

            if "Members" not in ethernet_data:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "'Members' not found in NetworkAdapters response, %s" % (ethernet_data)
                }

            for item in ethernet_data["Members"]:
                if "@odata.id" not in item:
                    return {
                        "ret": False,
                        "changed": False,
                        "msg": "'@odata.id' not found in NetworkAdapters response, %s" % (ethernet_data)
                    }
                # Get on each member eg : self.root_uri + self.service_root + /systems/1 + /BaseNetworkAdapters/1
                item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                if not item_rsp["ret"]:
                    return item_rsp

                mem_data = item_rsp["data"]
                # storing the result in a list
                nic.append(mem_data)

            return {
                "ret": True,
                "changed": False,
                "msg": nic
            }

        else:

            # Get on self.root_uri + self.service_root + /Chassis/1
            response = self.get_request(self.root_uri + self.service_root + "Chassis/1/")
            if not response["ret"]:
                return response

            json_data = response["data"]

            nic = []

            if "NetworkAdapters" not in json_data or "@odata.id" not in json_data["NetworkAdapters"]:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Network Adapters url not found in response, %s" % (json_data)
                }

            networkadapterurl = json_data["NetworkAdapters"]["@odata.id"]

            # Get on self.root_uri + self.service_root + /chassis/1 + /NetworkAdapters/
            nwk_adapt_rsp = self.get_request(self.root_uri + networkadapterurl)
            if not nwk_adapt_rsp["ret"]:
                return nwk_adapt_rsp

            nwk_adapt_rsp_data = nwk_adapt_rsp["data"]

            if "Members" not in nwk_adapt_rsp_data:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "'Members' not found in NetworkAdapters response, %s" % (nwk_adapt_rsp_data)
                }

            for item in nwk_adapt_rsp_data["Members"]:
                if "@odata.id" not in item:
                    return {
                    "ret": False,
                    "changed": False,
                    "msg": "'@odata.id' not found in NetworkAdapters response, %s" % (rsp_data)
                }
                # Get on each member eg : self.root_uri + self.service_root + /chassis/1 + /NetworkAdapters/<ID>
                item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                if not item_rsp["ret"]:
                    return item_rsp

                mem_data = item_rsp["data"]

                # Condition for DA**** and DE*****
                if "NetworkDeviceFunctions" in mem_data and "@odata.id" in mem_data["NetworkDeviceFunctions"]:
                    response = self.get_request(self.root_uri + mem_data["NetworkDeviceFunctions"]["@odata.id"])

                    if not response["ret"]:
                        return response
                    response_data = response["data"]

                    if "Members" not in response_data:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": response_data
                        }
                    rsp_list = []

                    for item in response_data["Members"]:
                        if "@odata.id" not in item:
                            return {
                                "ret": False,
                                "changed": False,
                                "msg": "'@odata.id' not found in Network device function response, %s" % (response_data)
                            }
                        # Get on each member eg : self.root_uri + self.service_root + /systems/1 + /
                        item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                        if not item_rsp["ret"]:
                            return item_rsp

                        nwk_device_fn_mem_data = item_rsp["data"]  
                        rsp_list.append(nwk_device_fn_mem_data) 

                    response_data["Members"] = rsp_list   
                    mem_data["NetworkDeviceFunctions"] = response_data
                

            # Get Port information 
                if "Ports" in mem_data and "@odata.id" in mem_data["Ports"]:
                    response = self.get_request(self.root_uri + mem_data["Ports"]["@odata.id"])

                    if not response["ret"]:
                        return response
                    response_data = response["data"]

                    if "Members" not in response_data:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": response_data
                        }    
                    rsp_list = []

                    for item in response_data["Members"]:
                        if "@odata.id" not in item:
                            return {
                                "ret": False,
                                "changed": False,
                                "msg": "'@odata.id' not found in Ports response, %s" % (response_data)
                            }
                        # Get on each member eg : self.root_uri + self.service_root + /systems/1 + /
                        item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                        if not item_rsp["ret"]:
                            return item_rsp

                        ports_mem_data = item_rsp["data"]  
                        rsp_list.append(ports_mem_data) 

                    response_data["Members"] = rsp_list  
                    mem_data["Ports"] = response_data
 
                # storing the result in a list
                nic.append(mem_data)

            return {
                "ret": True,
                "changed": False,
                "msg": nic
            }

    def get_certificate_authentication_data(self):
        response = self.get_request(self.root_uri + self.manager_uri)
        if not response["ret"]:
            return response

        security_service_uri = "Managers/1/SecurityService/"
        security_service = self.get_request(self.root_uri + self.service_root + security_service_uri)
        if not security_service["ret"]:
            return security_service

        security_service_data = security_service["data"]

        self.certificate_authentication_uri = security_service_data["Links"]["CertAuth"]["@odata.id"]
        certificate_authentication = self.get_request(self.root_uri + self.certificate_authentication_uri)      
        if not certificate_authentication["ret"]:
            return certificate_authentication

        return {
            "ret": True,
            "data": certificate_authentication["data"]
        }

    def get_trusted_ca_certificates(self):
        certificate_authentication = self.get_certificate_authentication_data()
        if not certificate_authentication["ret"]:
            return certificate_authentication

        certificate_authentication_data = certificate_authentication["data"]

        if "CACertificates" not in certificate_authentication_data or "@odata.id" not in \
            certificate_authentication_data["CACertificates"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "CA Certificates url not found in response, %s" % (certificate_authentication_data)
            }

        ca_certifcates_url = certificate_authentication_data["CACertificates"]["@odata.id"]
        ca_certificates = self.get_request(self.root_uri + ca_certifcates_url)      
        if not ca_certificates["ret"]:
            return ca_certificates
        ca_certificates_data = ca_certificates["data"]

        ca_certs = []
        for member in ca_certificates_data["Members"]:
            member_data = self.get_request(self.root_uri + member["@odata.id"])
            if not member_data["ret"]:
                return member_data

            ca_certs.append(member_data["data"])

        return {
            "ret": True,
            "msg": ca_certs
        }

    def set_spdm_settings(self, spdm_settings):
        # This function sets SPDM settings on an OOB controller

        # Validating inputs
        valid_spdm_settings = {
        "global_component_integrity": ["Enabled", "Disabled"], 
        "component_integrity_policy": ["NoPolicy", "HaltBootOnSPDMFailure"]}

        if spdm_settings is None or spdm_settings == {}:
            return {
                "ret": False,
                "changed": False,
                "msg": "'spdm_settings' is a mandatory parameter for SetSPDMSettings"
            }

        for key, value in valid_spdm_settings.items():
            if key not in spdm_settings.keys():
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "'%s' is a mandatory key parameter for dictionary spdm_settings" % str(key)
                }
            elif spdm_settings[key] not in value:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "%s parameter only supports %s. Provide one of these values to set SPDM settings." \
                            % (str(key), str(value))
                }

        # Get server details
        response = self.get_request(self.root_uri + self.service_root + "Managers/1/")
        if response["ret"] is False:
            return response
        server_details = response["data"]

        # Get security service url
        if "Oem" not in server_details or "Hpe" not in server_details["Oem"] or \
            "Links" not in server_details["Oem"]["Hpe"] or \
            "SecurityService" not in server_details["Oem"]["Hpe"]["Links"] or \
            "@odata.id" not in server_details["Oem"]["Hpe"]["Links"]["SecurityService"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Security Service url not found in response, %s" % (server_details)
            }
        security_service_url = server_details["Oem"]["Hpe"]["Links"]["SecurityService"]["@odata.id"]

        # Get security service data
        response = self.get_request(self.root_uri + security_service_url)
        if not response["ret"]:
            return response
        security_service_details = response["data"]

        # Set GlobalComponentIntegrity parameter
        body = {}
        body["GlobalComponentIntegrity"] = spdm_settings["global_component_integrity"]
        body["ComponentIntegrityPolicy"] = spdm_settings["component_integrity_policy"]

        res = self.patch_request(self.root_uri + security_service_url, body)
        if not res["ret"]:
            return res

        return {
            "ret": True,
            "changed": True,
            "msg": "GlobalComponentIntegrity %s. ComponentIntegrityPolicy set to %s. Server Power On required." \
                    % (spdm_settings["global_component_integrity"], spdm_settings["component_integrity_policy"])
        }

    def get_drive_operating_mode(self, ip_addr):
        # Get ArrayControllers
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response
        server_details = response["data"]

        if "Oem" not in server_details or "Hpe" not in server_details["Oem"] or \
            "Links" not in server_details["Oem"]["Hpe"] or \
            "SmartStorage" not in server_details["Oem"]["Hpe"]["Links"] or \
            "@odata.id" not in server_details["Oem"]["Hpe"]["Links"]["SmartStorage"]:
            return {
                "ret": False,
                "msg": "SmartStorage url not found in response, %s" % (server_details)
            }

        response = self.get_request(self.root_uri + server_details["Oem"]["Hpe"]["Links"]["SmartStorage"]["@odata.id"])
        if not response["ret"]:
            return response
        data = response["data"]

        if "Links" not in data or "ArrayControllers" not in data["Links"] or \
            "@odata.id" not in data["Links"]["ArrayControllers"]:
            return {
                "ret": False,
                "msg": "ArrayControllers url not found in response, %s" % (data)
            }

        response = self.get_request(self.root_uri + data["Links"]["ArrayControllers"]["@odata.id"])
        if not response["ret"]:
            return response
        init_data = response["data"]

        if response["data"]["Members@odata.count"] == 0:
            return {
                "ret": False,
                "msg": "No drive found in %s. Check the iLO" % res["data"]
            }
        # Get Members of ArrayControllers
        for mem in init_data["Members"]:
            mode_details = []
            array_url = mem["@odata.id"]

            array_res = self.get_request(self.root_uri + array_url)
            if not array_res["ret"]:
                return array_res

            json_data = array_res["data"]

            if 'CurrentOperatingMode' in json_data:
                mode_details.append({'ilo': ip_addr, 'operating_mode': json_data['CurrentOperatingMode']})
            else:
                return {
                    "ret": False,
                    "msg": "Current Operating Mode not found in %s response: %s" % (array_url, str(json_data))
                }

        return {
            "ret": True,
            "msg": mode_details
        }

    def import_trusted_ca(self, ca_file):
        certificate_authentication = self.get_certificate_authentication_data()
        if not certificate_authentication["ret"]:
            return certificate_authentication

        certificate_authentication_data = certificate_authentication["data"]

        import_trusted_ca_uri = certificate_authentication_data["Actions"]["#HpeCertAuth.ImportCACertificate"]["target"]

        cafile = open(ca_file)
        ca_file_data = cafile.readlines()

        ca_file_data = ca_file_data[ca_file_data.index("-----BEGIN CERTIFICATE-----\n"):ca_file_data.index("-----END CERTIFICATE-----\n")+1]
        ca_file_data = "".join(ca_file_data)

        payload = {
            "Certificate": ca_file_data
        }

        res = self.post_request(self.root_uri + import_trusted_ca_uri, payload)
        if not res["ret"]:
            if "Bad Request" in res["msg"]:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Importing trusted CA Certificate failed with response: " + res["msg"] + ". Certificate storage might be full, try again after cleaning up existing Trusted CA Certificates."
                }
            else:
                return res

        return {
            "ret": True,
            "changed": True,
            "msg": "Trusted CA imported"
        }

    def map_user_certificate(self, user_cert_file, username):
        certificate_authentication = self.get_certificate_authentication_data()
        if not certificate_authentication["ret"]:
            return certificate_authentication

        certificate_authentication_data = certificate_authentication["data"]

        user_certificate_mapping_uri = certificate_authentication_data["Links"]["UserCertificateMapping"]["@odata.id"]

        user_certificate_mapping_data = self.get_request(self.root_uri + user_certificate_mapping_uri)
        if not user_certificate_mapping_data["ret"]:
            return user_certificate_mapping_data

        flag = False
        for member in user_certificate_mapping_data["data"]["Members"]:
            member_request = self.get_request(self.root_uri + member["@odata.id"])
            if not member_request["ret"]:
                return member_request

            member_data = member_request["data"]

            if member_data["UserName"] == username:
                if member_data["Fingerprint"]:
                    if all(i != "00" for i in member_data["Fingerprint"].split(":")):
                        flag = True

        cert_file = open(user_cert_file)
        cert_file_data = cert_file.readlines()
        
        cert_file_data = cert_file_data[cert_file_data.index("-----BEGIN CERTIFICATE-----\n"):cert_file_data.index("-----END CERTIFICATE-----\n")+1]
        cert_file_data = "".join(cert_file_data)

        payload = {
            "Fingerprint": cert_file_data,
            "UserName": username
        }

        res = self.post_request(self.root_uri + user_certificate_mapping_uri, payload)
        if not res["ret"]:
            return res

        if flag:
            msg = "Certificate mapping already exists for this User. Replacing with new certifcate mapping."
        else:
            msg = "User certificate mapping is completed"

        return {
            "ret": True,
            "changed": True,
            "msg": msg
        }
        
    def erase_physical_drives(self):

        # Check if systems endpoint is present
        response = self.get_request(self.root_uri + self.systems_uri)
        if not response["ret"]:
            return response

        erase_url = "/redfish/v1/systems/1/smartstorageconfig/settings/"
        response = self.get_request(self.root_uri + erase_url)

        # Check if smartstorageconfig endpoint is present
        if not response["ret"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Operation not supported for iLO {}".format(self.root_uri)
            }

        physical_drives_list = response['data'].get('PhysicalDrives', [])

        if len(physical_drives_list) < 1:
            return {
                "ret": True,
                "changed": False,
                "msg": "No physical drives found in iLO {}".format(self.root_uri)
            }

        body = {
            "Actions": [
                {
                    "Action": "PhysicalDriveErase",
                    "ErasePattern": "ThreePass",
                    "PhysicalDriveList": []
                }
            ],
            "DataGuard": "Disabled"
        }

        for i in physical_drives_list:
            if "Location" in i:
                body["Actions"][0]["PhysicalDriveList"].append(i["Location"])

        response = self.patch_request(self.root_uri + erase_url, body)

        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "Cleanup successful. Total {} physical drives are erased. "
                   "System Reset required.".format(len(physical_drives_list))
        }

    def enable_certificate_login(self):
        certificate_authentication = self.get_certificate_authentication_data()
        if not certificate_authentication["ret"]:
            return certificate_authentication

        certificate_authentication_data = certificate_authentication["data"]

        if certificate_authentication_data["CertificateLoginEnabled"] == True:
            return {
                "ret": True,
                "changed": False,
                "msg": "Certificate Login is already enabled on the server"
            }
        else:
            payload = {"CertificateLoginEnabled": True}
            res = self.patch_request(self.root_uri + self.certificate_authentication_uri, payload)
            if not res["ret"]:
                return res

            return {
                "ret": True,
                "changed": True,
                "msg": "Certificate Login enabled"
            }

    def check_user_privileges(self):
        uri = "SessionService/Sessions/"
        response = self.get_request(self.root_uri + self.service_root + uri)
        if not response["ret"]:
            return response

        server_details = response["data"]

        response = self.get_request(self.root_uri + server_details["Oem"]["Hpe"]["Links"]["MySession"]["@odata.id"])
        if not response["ret"]:
            return response

        account_details = response["data"]
        account_privileges = []
        member_privileges = account_details["Oem"]["Hpe"]["Privileges"]

        for privilege, present in member_privileges.items():
            if present:
                account_privileges.append(privilege)

        return {
            "ret": True,
            "changed": False,
            "msg": "User %s has %s privileges" % (account_details["UserName"], account_privileges)
        }

    def get_device_inventory_info(self):
                        
        chassis_url = self.service_root + "Chassis/"
        res = self.get_request(self.root_uri + chassis_url)
        if not res["ret"]:
            return {
                "ret": False,
                "msg": "Failed to get details from %s" % chassis_url
            }
        if res["data"]["Members@odata.count"] == 0:
            return {
                "ret": False,
                "msg": "Failed to get details from %s" % res["data"]["Members@odata.count"]
            }

        # Get Members of ArrayControllers
        for mem in res["data"]["Members"]:
            array_url = mem["@odata.id"]
            if "enclosurechassis" in array_url:
                continue

            array_res = self.get_request(self.root_uri + array_url)
            if not array_res["ret"]:
                return {
                    "ret": False,
                    "msg": "Failed to get details from %s" % array_url
                }

            # Get device detail URI
            if 'Oem' in array_res["data"] and 'Hpe' in array_res["data"]['Oem']:
                log_url = array_res["data"]['Oem']['Hpe']['Links']['Devices']['@odata.id']
            else:
                return {
                    "ret": False,
                    "msg": "Device details URI not found in %s" % array_url
                }
            # Get list of device details URI
            device_details_resp1 = self.get_request(self.root_uri + log_url)
            if not device_details_resp1["ret"]:
                return {
                    "ret": False,
                    "msg": "Failed to get details from %s" % log_url
                }
            final_details = []
            for entry in device_details_resp1["data"]["Members"]:
                # Get each device details
                log = self.get_request(self.root_uri + entry["@odata.id"])
                if not log["ret"]:
                    return {
                        "ret": False,
                        "msg": "Failed to get details from %s" % entry["@odata.id"]
                    }
                device_details = log["data"]
                device_list = []
                if "DeviceInstances" in device_details:
                    for instance in device_details["DeviceInstances"]:
                        pci_device_details = self.get_request(self.root_uri + instance["@odata.id"])
                        if not pci_device_details["ret"]:
                            return {
                                "ret": False,
                                "msg": "Failed to get details from %s" % instance["@odata.id"]
                            }
                        device_list.append(pci_device_details["data"])
                    device_details["DeviceInstances"] = device_list
                final_details.append(device_details)

        return {
            "ret": True,
            "msg": final_details
        }

    def install_helper(self, client, sudo_password, filename, remote, op_sys, architecture):

        result = {}
        found = False
        nodir = False
        error_output = ""

        command = f"ls /usr/lib/{architecture}/"
        stdin, stdout, stderr = client.exec_command(command)
        error_output = stderr.read().decode('utf-8')
        if len(error_output) > 0:
            if "No such file or directory" in error_output:
                nodir = True
            else:
                result["ret"] = False
                result["msg"] = error_output
                return result

        if not nodir:
            output = stdout.read().decode('utf-8').split("\n")
            package = filename[:-4]

            for pack in output:
                if pack in package:
                    if op_sys == "apt":
                        package = package.split("_")[0]
                    command = f'sudo -p "" {op_sys} remove -y {package}'
                    stdin, stdout, stderr = client.exec_command(
                        command, get_pty=True)
                    stdin.write(sudo_password + '\n')
                    stdin.flush()
                    time.sleep(10)
                    break

            for files in output:
                if "scexe-compat" in files:
                    found = True
                    break

            if found:
                command = f'sudo -p "" rm -f /usr/lib/{architecture}/scexe-compat/*'
                stdin, stdout, stderr = client.exec_command(
                    command, get_pty=True)
                stdin.write(sudo_password + '\n')
                stdin.flush()
                error_output = stderr.read().decode('utf-8')
                if len(error_output) > 0:
                    result["ret"] = False
                    result["msg"] = error_output
                    return result
                found = False

        command = f'sudo -p "" {op_sys} install -y {remote}{filename}'
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        stdin.write(sudo_password + '\n')
        stdin.flush()
        time.sleep(10)

        return result

    def install_rpm(self, rpm_info):

        username = rpm_info["os_username"]
        password = rpm_info["os_password"]
        remote_ip = rpm_info["OSIP"]
        remote = rpm_info['remote']
        filename = rpm_info['file_name']

        result = {}
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(remote_ip, username=username, password=password)

        command = "cat /etc/os-release | grep -w 'ID' | cut -d '=' -f 2"
        output = ""
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8').split("\n")
        error_output = stderr.read().decode('utf-8')
        if len(error_output) > 0:
            result["ret"] = False
            result["msg"] = error_output
            return result

        command = "uname -a"
        stdin, stdout, stderr = client.exec_command(command)
        architecture = stdout.read().decode('utf-8').split("\n")[0]
        error_output = stderr.read().decode('utf-8')
        if len(error_output) > 0:
            result["ret"] = False
            result["msg"] = error_output
            return result

        for os_in_op in output:

            if "ubuntu" in os_in_op and "aarch64" in architecture:
                op_sys = "apt"
                architecture = "aarch64-linux-gnu"
                result = self.install_helper(
                    client, password, filename, remote, op_sys, architecture)

                if result:
                    return result
                break

            elif "ubuntu" in os_in_op and "x86_64" in architecture:
                op_sys = "apt"
                architecture = "x86_64-linux-gnu"
                result = self.install_helper(
                    client, password, filename, remote, op_sys, architecture)

                if result:
                    return result
                break

            elif "rhel" in os_in_op and "x86_64" in architecture:
                op_sys = "yum"
                architecture = "x86_64-linux-gnu"
                result = self.install_helper(
                    client, password, filename, remote, op_sys, architecture)

                if result:
                    return result
                break

            elif "rhel" in os_in_op and "aarch64" in architecture:
                op_sys = "yum"
                architecture = "aarch64-linux-gnu"
                result = self.install_helper(
                    client, password, filename, remote, op_sys, architecture)

                if result:
                    return result
                break

            else:
                result = {}
                result["ret"] = False
                result["msg"] = "Architecture not supported.\n"
                return result

        client.close()
        result = {}
        result["ret"] = True
        result["msg"] = filename + " installed successfully."
        result["changed"] = True
        return result

    def install_smartcomp(self, rpm_info):

        username = rpm_info["os_username"]
        password = rpm_info["os_password"]
        remote_ip = rpm_info["OSIP"]

        result = {}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(remote_ip, username=username, password=password)

        command = "uname -a"
        stdin, stdout, stderr = client.exec_command(command)
        architecture = stdout.read().decode('utf-8').split("\n")[0]
        error_output = stderr.read().decode('utf-8')
        if len(error_output) > 0:
            result["ret"] = False
            result["msg"] = error_output
            return result

        smcp_file = ""

        if "x86_64" in architecture:
            smcp_file = "x86_64-linux-gnu"
        elif "aarch64" in architecture:
            smcp_file = "aarch64-linux-gnu"
        else:
            result["ret"] = False
            result["msg"] = "Architecture not supported."
            return result

        command = "ls /usr/lib/"+smcp_file+"/scexe-compat"
        stdin, stdout, stderr = client.exec_command(command)
        smart_component = stdout.read().decode('utf-8')
        error_output = stderr.read().decode('utf-8')
        if len(error_output) > 0:
            result["ret"] = False
            result["msg"] = error_output
            return result

        smart_component_path = "/usr/lib/" + smcp_file + \
            "/scexe-compat/" + smart_component.strip()

        command = 'sudo -p "" chmod +x ' + smart_component_path
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        stdin.write(password + '\n')
        stdin.flush()
        error_output = stderr.read().decode('utf-8')
        if len(error_output) > 0:
            result["ret"] = False
            result["msg"] = error_output
            return result

        command = 'sudo -p "" ' + smart_component_path
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        stdin.write(password + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8')
        error_output = stderr.read().decode('utf-8')
        client.close()
        if len(error_output) > 0:
            result["ret"] = False
            result["msg"] = error_output
            return result

        message = output.replace('\n', '')
        result["ret"] = True
        result["msg"] = message
        result["changed"] = True
        return result

    def get_hostname(self):
        # Get on redfish/v1 collection
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if "Oem" in data and "Hpe" in data["Oem"] and "Manager" in data["Oem"]["Hpe"] and "HostName" in data["Oem"]["Hpe"]["Manager"][0]:
            return {
            "ret": True,
            "msg": data["Oem"]["Hpe"]["Manager"][0]["HostName"]
        }

        return {
            "ret": False,
            "msg": "HostName could not be found."
        }

    def firmware_upgrade_with_upload(self,image_uri,file_name,upgrade = True):
        # This method upgrades the firmware image along with uploading to iLO repository
        # Get on self.root_uri + self.service_root + /UpdateService
        response = self.get_updateservice_data()
        if not response["ret"]:
            return response

        json_data = response["msg"]["data"]  
        if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or "Actions" not in json_data["Oem"]["Hpe"] or \
            "#HpeiLOUpdateServiceExt.AddFromUri" not in json_data["Oem"]["Hpe"]["Actions"] or \
            "target" not in json_data["Oem"]["Hpe"]["Actions"]["#HpeiLOUpdateServiceExt.AddFromUri"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "target url not found in the response, %s" %(json_data["data"])
            }
        # check the file already present in the server or not
        ilo_repo_rsp = self.get_ilo_repo_details()
        if not ilo_repo_rsp["ret"]:
            return ilo_repo_rsp
        
        for each_file_name in ilo_repo_rsp["msg"]["Members"]:
            if( (each_file_name["Filename"] == file_name or (file_name == '' and each_file_name["Filename"] == image_uri.split('/')[-1]) ) and each_file_name["Locked"]):
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "The file with name '%s' already exists in the repository and is locked. Remove the install set or task that is locking the component and try again." %(each_file_name["Filename"])
                }

        update_url = self.root_uri + json_data["Oem"]["Hpe"]["Actions"]["#HpeiLOUpdateServiceExt.AddFromUri"]["target"]
        body = {
            "ImageURI": image_uri,
            "UpdateRepository": True,
            "UpdateTarget": upgrade,
            "TPMOverrideFlag": True
        }

        if(file_name != ''):
            body["ComponentFileName"] = file_name

        response = self.post_request(update_url,body)
        if not response["ret"]:
            return response

        data = response["resp"]        
        json_data = json.loads(data.read().decode('utf8'))
        return {
            "ret": True,
            "changed": True,
            "msg": json_data
        }

    def get_maintenance_window(self):
        # This method outputs all the maintenance windows details present in server.
        # Get on self.root_uri + self.service_root + /UpdateService
        response = self.get_updateservice_data()
        if not response["ret"]:
            return response

        json_data = response["msg"]["data"]

        if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or \
            "MaintenanceWindows" not in json_data["Oem"]["Hpe"] or \
            "@odata.id" not in json_data["Oem"]["Hpe"]["MaintenanceWindows"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Maintenance window url not found in response, %s" % (json_data)
            }

        maintenance_window_url = json_data["Oem"]["Hpe"]["MaintenanceWindows"]["@odata.id"]

        # Get on self.root_uri + self.service_root + /UpdateService + /MaintenanceWindows/
        maintenance_window_rsp = self.get_request(self.root_uri + maintenance_window_url)
        if not maintenance_window_rsp["ret"]:
            return maintenance_window_rsp

        maintenance_window_data = maintenance_window_rsp["data"]
        maintenance_window_details = []
        if maintenance_window_data["Members"]:
            for item in maintenance_window_data["Members"]:
                # Get on each member eg : self.root_uri + self.service_root + /UpdateService + /MaintenanceWindows/ + 7ecdco/
                item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                if not item_rsp["ret"]:
                    return item_rsp

                mem_data = item_rsp["data"]
                # storing the result in a list
                maintenance_window_details.append(mem_data)
    
        return {
            "ret": True,
            "changed": False,
            "msg": maintenance_window_details
        }

    def create_maintenance_window(self,maintenance_window_data):
        # This method creates a new maintenance window and outputs the id of it.
        # Get on self.root_uri + self.service_root + /UpdateService
        response = self.get_updateservice_data()
        if not response["ret"]:
            return response

        json_data = response["msg"]["data"]

        if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or \
            "MaintenanceWindows" not in json_data["Oem"]["Hpe"] or \
            "@odata.id" not in json_data["Oem"]["Hpe"]["MaintenanceWindows"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Maintenance window url not found in response, %s" % (json_data)
            }

        maintenance_window_url = json_data["Oem"]["Hpe"]["MaintenanceWindows"]["@odata.id"]

        # Check whether the start time is greater than expire time

        start_time = datetime.strptime(maintenance_window_data["StartAfter"], "%Y-%m-%dT%H:%M:%SZ")
        end_time = datetime.strptime(maintenance_window_data["Expire"], "%Y-%m-%dT%H:%M:%SZ") 

        if(start_time > end_time):
            return {
                "ret": False,
                "changed": False,
                "msg": "Provided StartAfter time should be earlier than the Expire time"
            }
        response = self.get_request(self.root_uri + self.service_root )
        if not response["ret"]:
            return response

        ilo_time = ''
        if "Oem" in response["data"] and "Hpe" in response["data"]["Oem"] and "Time" in response["data"]["Oem"]["Hpe"]:
            ilo_time = response["data"]["Oem"]["Hpe"]["Time"]

        ilo_time = datetime.strptime(ilo_time, "%Y-%m-%dT%H:%M:%SZ")

        # Check for maintenance window will expire before it is created
        if (ilo_time > end_time):
            return {
               "ret": False,
               "changed": False,
               "msg": "Provided Expire time should be later than the iLO server time"               
            }


        maintenance_window_body = {          
           "Name": str(maintenance_window_data["Name"]),
           "StartAfter": maintenance_window_data["StartAfter"],
           "Expire": maintenance_window_data["Expire"]
        }

        if "maintenance_window_description" in maintenance_window_data:
            maintenance_window_body["Description"].append(str(maintenance_window_data["Description"]))
        response = self.post_request(self.root_uri + maintenance_window_url, maintenance_window_body)

        if not response["ret"]:
            return response

        data = response["resp"]        

        json_data = json.loads(data.read().decode('utf8'))
        maintenance_window_id = json_data["Id"]
        return {
            "ret": True,
            "changed": True,
            "msg": maintenance_window_id
        }        
         
    def get_task_queue_details(self):
        # This method outputs all the tasks present in the installation queue.
        # Get on self.root_uri + self.service_root + /UpdateService
        response = self.get_updateservice_data()
        if not response["ret"]:
            return response

        json_data = response["msg"]["data"]
        if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or \
            "UpdateTaskQueue" not in json_data["Oem"]["Hpe"] or \
            "@odata.id" not in json_data["Oem"]["Hpe"]["UpdateTaskQueue"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Update task queue url not found in response, %s" % (json_data)
            }  

        # GET on /redfish/v1/UpdateService/UpdateTaskQueue/
        update_task_queue_url = json_data["Oem"]["Hpe"]["UpdateTaskQueue"]["@odata.id"]
        update_task_queue_rsp = self.get_request(self.root_uri + update_task_queue_url )

        if not update_task_queue_rsp["ret"]:
            return update_task_queue_rsp    

        update_task_queue_rsp_data = update_task_queue_rsp["data"]

        task_queue_details = []
        if update_task_queue_rsp_data["Members"]:
            for item in update_task_queue_rsp_data["Members"]:
                # Get on each member eg : self.root_uri + self.service_root + /UpdateService + /UpdateTaskQueue/ + 7ecdco/
                item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                if not item_rsp["ret"]:
                    return item_rsp

                mem_data = item_rsp["data"]
                # storing the result in a list
                task_queue_details.append(mem_data)
    
        return {
            "ret": True,
            "changed": False,
            "msg": task_queue_details
        }   

    def get_all_install_sets(self):
        # This method outputs all the install sets details present in the server.
        # Get on self.root_uri + self.service_root + /UpdateService
        response = self.get_updateservice_data()
        if not response["ret"]:
            return response

        json_data = response["msg"]["data"]

        if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or \
            "InstallSets" not in json_data["Oem"]["Hpe"] or \
            "@odata.id" not in json_data["Oem"]["Hpe"]["InstallSets"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Install set url not found in response, %s" % (json_data)
            }  
        install_set_url = json_data["Oem"]["Hpe"]["InstallSets"]["@odata.id"]
        # Get on self.root_uri + self.service_root + /UpdateService/InstallSets
        install_set_rsp = self.get_request(self.root_uri + install_set_url)
        if not install_set_rsp["ret"]:
            return install_set_rsp

        install_set_rsp_data = install_set_rsp["data"]

        install_set_details = []
        if install_set_rsp_data["Members"]:
            for item in install_set_rsp_data["Members"]:
                # Get on each member eg : self.root_uri + self.service_root + /UpdateService + /InstallSets/ + 7ecdco/
                item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                if not item_rsp["ret"]:
                    return item_rsp

                mem_data = item_rsp["data"]
                # storing the result in a list
                install_set_details.append(mem_data)
        install_set_rsp_data["Members"] = install_set_details

        return {
            "ret": True,
            "changed": False,
            "msg": install_set_rsp_data
        }   

    def create_install_set(self,install_set_url,install_set_attributes):
        # This method creates new install set and outputs the same.
        # POST on self.root_uri + self.service_root + /UpdateService/InstallSets
        # Creating install set body 
        install_set_body = {          
           "Name": str(install_set_attributes["Name"]),
           "Sequence": install_set_attributes["Install_set_sequence"]
        }
        if(install_set_attributes["Description"]!=''):
            install_set_body["Description"] = install_set_attributes["Description"]

        response = self.post_request(self.root_uri + install_set_url, install_set_body)

        if not response["ret"]:
            return response

        data = response["resp"]        
        json_data = json.loads(data.read().decode('utf8')) 

        return {
            "ret": True,
            "changed": True,
            "msg": json_data            
        }

    def get_ilo_repo_details(self):
        # This method outputs all the file's details present in the iLO repository      
        # Get on self.root_uri + self.service_root + /UpdateService
        response = self.get_updateservice_data()
        if not response["ret"]:
            return response

        json_data = response["msg"]["data"]

        if "Oem" not in json_data or "Hpe" not in json_data["Oem"] or \
            "ComponentRepository" not in json_data["Oem"]["Hpe"] or \
            "@odata.id" not in json_data["Oem"]["Hpe"]["ComponentRepository"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "Component repository url not found in response, %s" % (json_data)
            }  

        component_repository_url = json_data["Oem"]["Hpe"]["ComponentRepository"]["@odata.id"]
        # Get on self.root_uri + self.service_root + /UpdateService/ComponentRepository
        comp_repo_rsp = self.get_request(self.root_uri + component_repository_url)
        if not comp_repo_rsp["ret"]:
            return comp_repo_rsp

        comp_repo_rsp_data = comp_repo_rsp["data"]

        ilo_repo_details = []
        if comp_repo_rsp_data["Members"]:
            for item in comp_repo_rsp_data["Members"]:
                # Get on each member eg : self.root_uri + self.service_root + /UpdateService + /ComponentRepository/ + 7ecdco/
                item_rsp = self.get_request(self.root_uri + item["@odata.id"])
                if not item_rsp["ret"]:
                    return item_rsp

                mem_data = item_rsp["data"]
                # storing the result in a list
                ilo_repo_details.append(mem_data)
        comp_repo_rsp_data["Members"] = ilo_repo_details

        return {
            "ret": True,
            "changed": False,
            "msg": comp_repo_rsp_data
        }           

    def get_maintenance_window_id(self,maintenance_window_details):
        # Get maintenance window details
        resp = self.get_maintenance_window()
        if not resp["ret"]:
            return resp 
        resp_data = resp["msg"]

        ilo_time = ''
        response = self.get_request(self.root_uri + self.service_root )
        if not response["ret"]:
            return response

        if "Oem" in response["data"] and "Hpe" in response["data"]["Oem"] and "Time" in response["data"]["Oem"]["Hpe"]:
            ilo_time = response["data"]["Oem"]["Hpe"]["Time"]    
        ilo_time = datetime.strptime(ilo_time, "%Y-%m-%dT%H:%M:%SZ")

        maintenance_window_id = '' 
        if "StartAfter" in maintenance_window_details.keys() and "Expire" in maintenance_window_details.keys():
            for each in resp_data:
                if each["Name"] == maintenance_window_details["Name"]:
                    # check start and end time
                    if maintenance_window_details["StartAfter"] != each["StartAfter"] or \
                        maintenance_window_details["Expire"] != each["Expire"]:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Maintenance window with same name with different start and expire time already exists in the server. Hence provide unique name for maintenance window"
                        }
                    else: 
                        end_time = datetime.strptime(maintenance_window_details["Expire"], "%Y-%m-%dT%H:%M:%SZ")
                        # Check for maintenance window will expire before it is created
                        if (ilo_time > end_time):
                            return {
                                "ret": False,
                                "changed": False,
                                "msg": "Provided Expire time should be later than the iLO server time"               
                            }
                        maintenance_window_id = each["Id"]

            if maintenance_window_id == "":
                if len(resp_data) >=8:
                    return {
                        "ret": False,
                        "changed": False,
                        "msg": "The maximum number of maintenance windows has been reached. Remove unneeded maintenance windows and try again."
                    }
                resp = self.create_maintenance_window(maintenance_window_details)
                if not resp["ret"]:
                    return resp    
                maintenance_window_id = resp["msg"]  
        else:
            for each in resp_data:
                if each["Name"] == maintenance_window_details["Name"]:
                    end_time = datetime.strptime(each["Expire"], "%Y-%m-%dT%H:%M:%SZ")

                    # Check for maintenance window will expire before it is created
                    if (ilo_time > end_time):
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Provided Expire time should be later than the iLO server time"               
                        }
                    maintenance_window_id = each["Id"]
            if maintenance_window_id == "":
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "No maintenance window with the name '%s' found in the server" % (maintenance_window_details["Name"])
                }

        return {
            "ret": True,
            "changed": False,
            "msg": maintenance_window_id        
        }

    def get_install_set_url(self,install_set_attributes):
        # This method upgrades the firmware through provided install set sequence
        install_set_resp = self.get_all_install_sets()
        if not install_set_resp["ret"]:
            return install_set_resp

        install_set_url = install_set_resp["msg"]["@odata.id"]

        found_install_set = False
        for each_mem in install_set_resp["msg"]["Members"]:  
            # Check name of install set name 
            if install_set_attributes["Name"] == each_mem["Name"]:
                found_install_set = True
                # Check for sequence 
                if (len(install_set_attributes["Install_set_sequence"]) != len(each_mem["Sequence"])):
                    return {
                        "ret": False,
                        "changed": False,
                        "msg": "Install set with same name already exists in the server with different sequence. Hence provide unique name for install set"                         
                    }                    
                # Check the each task in the sequence 
                for i in range(len(install_set_attributes["Install_set_sequence"])):
                    if install_set_attributes["Install_set_sequence"][i]["Filename"] != each_mem["Sequence"][i]["Filename"]:
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "Install set with same names already exists in the server with different sequence. Hence provide unique name for install set"                         
                        }
                install_set_invoke_url = self.root_uri + each_mem["Actions"]["#HpeComponentInstallSet.Invoke"]["target"]
                
        # Check all the files in the sequence present in server
        ilo_resp = self.get_ilo_repo_details()
        if not ilo_resp["ret"]:
            return ilo_resp
        
        for each_filename in install_set_attributes["Install_set_sequence"]:
            file_found = False
            for each in ilo_resp["msg"]["Members"]:
                if each_filename["Filename"] == each["Filename"]:
                    file_found = True
            if not file_found:
                return{
                    "ret": False,
                    "changed": False,
                    "msg": "Provided filename %s doesn't exist in ilo repository" %(each_filename["Filename"])
                }

        if not found_install_set:
            if len(install_set_resp["msg"]["Members"]) >=8:
                return {
                    "ret": False,
                    "changed": False,
                    "msg": "Maximum of 8 install sets can be created. To create a new install set, please delete unneeded install sets and try again."
                }
            resp = self.create_install_set(install_set_url,install_set_attributes)
            if not resp["ret"]:
                return resp
            install_set_invoke_url = self.root_uri +  resp["msg"]["Actions"]["#HpeComponentInstallSet.Invoke"]["target"]

        return {
            "ret": True,
            "changed": False,
            "msg": install_set_invoke_url        
        }

    def firmware_upgrade_through_install_set(self,install_set_attributes,maintenance_window_details):
        # If the sequence doesn't have UpdatableBy parameter, add by default as Bmc
        for each_sequence in install_set_attributes["Install_set_sequence"]:
            each_sequence["Command"] = "ApplyUpdate"
            if "UpdatableBy" not in each_sequence:
                each_sequence["UpdatableBy"] = ["Bmc"]

        install_set_url_rsp = self.get_install_set_url(install_set_attributes)
        if not install_set_url_rsp["ret"]:
            return install_set_url_rsp        
        install_set_invoke_url = install_set_url_rsp["msg"]

        maintenance_window_id = ''

        # Check maintenance window provided 
        if maintenance_window_details:
            maintenance_window_id_rsp = self.get_maintenance_window_id(maintenance_window_details)
            if not maintenance_window_id_rsp["ret"]:
                return maintenance_window_id_rsp            
            maintenance_window_id = maintenance_window_id_rsp["msg"]
        
        install_set_invoke_body = {
               "TPMOverride": True
        }

        # Mapping of maintenance window id if applicable
        if maintenance_window_id !='':
            install_set_invoke_body["MaintenanceWindow"] = maintenance_window_id

        # Check any of the task in the sequence is running
        resp = self.get_task_queue_details()
        if not resp["ret"]:
            return resp["ret"]

        for each_name in resp["msg"]:
            for each_mem in install_set_attributes["Install_set_sequence"]:
                # Collect id's if the task name in installation_queue matches with task name provided in install set sequence input
                if each_mem["Name"] == each_name["Name"]:
                    # Clear the task if it is not in running state
                    if each_name["State"] in ["Complete","Expire","Exception","Canceled"]:
                        del_rsp = self.delete_request(self.root_uri + each_name["@odata.id"])
                        if not del_rsp["ret"]:
                            return del_rsp
                    else:      
                        return {
                            "ret": False,
                            "changed": False,
                            "msg": "The items in the install set could not be queued. An installation task with one of those items may already exist."
                        }

        # Invoke install set
        # POST on self.root_uri + self.service_root + /UpdateService/InstallSets/ + ID + /Actions/HpeComponentInstallSet.Invoke/
        response = self.post_request(install_set_invoke_url, install_set_invoke_body)
        if not response["ret"]:
            return response

        # Get the current tasks present in the installation queue after the post operation 
        resp = self.get_task_queue_details()
        if not resp["ret"]:
            return resp

        result_list = []
        
        for each_name in resp["msg"]:
            result_dict = {}
            for each_mem in install_set_attributes["Install_set_sequence"]:
                # Collect id's if the task name in installation_queue matches with task name provided in install set sequence input
                if each_mem["Name"] == each_name["Name"]:
                    result_dict["ID"] = each_name["Id"]
                    result_dict["URL"] = each_name["@odata.id"]
                    result_list.append(result_dict)

        return {
            "ret": True,
            "changed": True,
            "msg": result_list
        }   
                
    def get_firmware_status(self):
        # This method checks the firmware upgrade status and outputs the state,Url and Id of the tasks.
        # Get on self.root_uri + self.service_root + /TaskService
        response = self.get_taskservice_data()
        if not response["ret"]:
            return response    

        json_data = response["msg"]["data"]  
        if "Tasks" not in json_data or "@odata.id" not in json_data["Tasks"]:
            return {
                "ret": False,
                "changed": False,
                "msg": "'@odata.id' not found in task service response, %s" % (json_data)
            }
        # Get on self.root_uri + self.service_root + /TaskService + /Tasks
        item_rsp = self.get_request(self.root_uri + json_data["Tasks"]["@odata.id"])
        if not item_rsp["ret"]:
            return item_rsp

        taskservice_mem_data_ids = []
        if item_rsp["data"]["Members"]:
            taskservice_mem_data_ids = item_rsp["data"]["Members"]

        # Get on /redfish/v1/UpdateService/UpdateTaskQueue/
        task_queue_rsp = self.get_task_queue_details()
        if not task_queue_rsp["ret"]:
            return task_queue_rsp["ret"]
        updateservice_mem_data_ids = []

        for task in task_queue_rsp["msg"]:
            tmp_dict = {}
            tmp_dict["@odata.id"] = task['@odata.id']
            updateservice_mem_data_ids.append(tmp_dict)

        # Concatenate data ids of tasks from both updateservice and taskservice into single dict
        total_mem_data_ids = taskservice_mem_data_ids + updateservice_mem_data_ids

        task_ids_status = []

        # Check all the tasks in updateservice and specific in taskservice
        total_mem_data_ids = updateservice_mem_data_ids
        for each_mem in taskservice_mem_data_ids:
            resp = self.get_request(self.root_uri + each_mem['@odata.id'])
            if not resp["ret"]:
                return resp
            if "UpdateService.SimpleUpdate" in resp["data"]["Payload"]["TargetUri"] or \
                "HpeiLOUpdateServiceExt.AddFromUri" in resp["data"]["Payload"]["TargetUri"] or \
                "HpeComponentInstallSet.Invoke" in resp["data"]["Payload"]["TargetUri"]:
                total_mem_data_ids.append(each_mem) 

        for each_member in total_mem_data_ids:
            task_details = {}
            curstate = ''
            task_id = ''

            each_item_rsp = self.get_request(self.root_uri + each_member["@odata.id"])

            if not each_item_rsp["ret"]:
                return each_item_rsp 

            task_id = each_item_rsp["data"]["Id"]
            if "TaskState" in each_item_rsp["data"]:
                curstate = each_item_rsp["data"]["TaskState"]
            else:
                curstate = each_item_rsp["data"]["State"]


            if "Messages" in each_item_rsp["data"] and (curstate != "Completed" and curstate != "Complete") and \
                isinstance(each_item_rsp["data"]["Messages"],list) and len(each_item_rsp["data"]["Messages"])!=0 and \
                "MessageId" in each_item_rsp["data"]["Messages"][0]:
                task_details["Msg"] = each_item_rsp["data"]["Messages"][0]["MessageId"]
            if "Result" in each_item_rsp["data"] and "MessageId" in each_item_rsp["data"]["Result"]:
                task_details["Msg"] = each_item_rsp["data"]["Result"]["MessageId"]  

            # Store the result in dict
            task_details["ID"] = task_id
            task_details["State"] = curstate 
            task_details["URL"] = each_member["@odata.id"]
            
            task_ids_status.append(task_details)            

        response = self.get_updateservice_data()
        if not response["ret"]:
            return response    

        json_data = response["msg"]["data"]  

        flash_progress_percentage = 'NA'
        if "Oem" in json_data and "Hpe" in json_data["Oem"] and "FlashProgressPercent" in json_data["Oem"]["Hpe"] :
            flash_progress_percentage = str(json_data["Oem"]["Hpe"]["FlashProgressPercent"]) + "%"

        if len(task_ids_status) == 0:
            return {
                "ret": True,
                "changed": False,
                "msg": "No tasks are available in the server"
            }

        return {
            "ret": True,
            "changed": False,
            "flash_progress_percentage": flash_progress_percentage,
            "msg": task_ids_status
        }
