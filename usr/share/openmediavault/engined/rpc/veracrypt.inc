<?php
/**
 * @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    OMV Plugin Developer <plugins@omv-extras.org>
 * @copyright Copyright (c) 2026 openmediavault plugin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

require_once("openmediavault/globals.inc");
require_once("openmediavault/functions.inc");

class OMVRpcServiceVeraCrypt extends \OMV\Rpc\ServiceAbstract
{
    private function logDebug($message)
    {
        // Debugging disabled
    }

    public function getName()
    {
        return "VeraCrypt";
    }

    public function initialize()
    {
        $this->registerMethod("get");
        $this->registerMethod("set");
        $this->registerMethod("getProfileList");
        $this->registerMethod("getProfileDetails");
        $this->registerMethod("setProfile");
        $this->registerMethod("deleteProfile");
        $this->registerMethod("mount");
        $this->registerMethod("mountManual");
        $this->registerMethod("unmount");
        $this->registerMethod("createContainer");
        $this->registerMethod("installVeraCrypt");
        $this->registerMethod("removeVeraCrypt");
        $this->registerMethod("getStatus");
        $this->registerMethod("getMountedVolumes");
        $this->registerMethod("getMountedVolumesList");
        $this->registerMethod("unmountAll");
        $this->registerMethod("unmountMultiple");
        $this->registerMethod("checkInstall");
        $this->registerMethod("listMountedVolumes");
    }

    private function generateUuid4()
    {
        if (class_exists('\OMV\Utils\Uuid')) {
            return \OMV\Utils\Uuid::uuid4();
        }
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    private function filterProfileData($profile)
    {
        $allowedKeys = [
            "uuid",
            "shared_folder_uuid",
            "name",
            "type",
            "container_location",
            "endpoint_folder",
            "password",
            "permissions",
            "save_password"
        ];
        $filtered = [];
        foreach ($allowedKeys as $key) {
            if (isset($profile[$key])) {
                $filtered[$key] = $profile[$key];
            } else {
                if ($key === "permissions") {
                    $filtered[$key] = "777";
                } elseif ($key === "type") {
                    $filtered[$key] = "file";
                } elseif ($key === "save_password") {
                    $filtered[$key] = false;
                } else {
                    $filtered[$key] = "";
                }
            }
        }
        return $filtered;
    }

    private function getConfigObject()
    {
        $db = \OMV\Config\Database::getInstance();
        try {
            return $db->get("conf.service.veracrypt");
        } catch (\Exception $e) {
            $cmd = new \OMV\System\Process("omv-confdbadm", ["create", "conf.service.veracrypt"]);
            $cmd->execute();
            return $db->get("conf.service.veracrypt");
        }
    }

    public function get($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $object = $this->getConfigObject();
        return $object->getAssoc();
    }

    public function set($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.set");

        $db = \OMV\Config\Database::getInstance();
        $object = $this->getConfigObject();

        // Handle profile modifications (e.g. if remember_configs or save_password is false, clear password)
        if (isset($params['profiles']) && isset($params['profiles']['profile'])) {
            $existingConfig = $this->getConfigObject();
            $existingProfiles = $existingConfig->get("profiles") ? $existingConfig->get("profiles") : [];
            $existingProfilesList = isset($existingProfiles['profile']) ? $existingProfiles['profile'] : [];

            $existingPasswords = [];
            foreach ($existingProfilesList as $ep) {
                if (isset($ep['uuid'])) {
                    $existingPasswords[$ep['uuid']] = isset($ep['password']) ? $ep['password'] : '';
                }
            }

            $profiles = [];
            foreach ($params['profiles']['profile'] as $profile) {
                if (isset($profile['remember_configs']) && !$profile['remember_configs']) {
                    $profile['password'] = "";
                }

                $pUuid = isset($profile['uuid']) ? $profile['uuid'] : '';
                $oldP = isset($existingPasswords[$pUuid]) ? $existingPasswords[$pUuid] : '';
                $newP = isset($profile['password']) ? $profile['password'] : '';

                if ($newP !== $oldP) {
                    if (isset($profile['save_password']) && $profile['save_password']) {
                        if (!empty($newP)) {
                            $profile['password'] = base64_encode($newP);
                        }
                    } else {
                        $profile['password'] = "";
                    }
                } else {
                    $profile['password'] = $oldP;
                }
                $profiles[] = $this->filterProfileData($profile);
            }
            $params['profiles']['profile'] = $profiles;
        }

        $object->setAssoc($params);
        $db->set($object);
        return $object->getAssoc();
    }

    private function isVeraCryptInstalled()
    {
        try {
            $proc = new \OMV\System\Process("veracrypt", ["-t", "--version"]);
            $proc->execute($output, $exitStatus);
            if ($exitStatus === 0) {
                return true;
            }
        } catch (\Exception $e) {
            // ignore
        }
        $testPaths = [
            "/usr/bin/veracrypt",
            "/usr/sbin/veracrypt",
            "/usr/local/bin/veracrypt",
            "/bin/veracrypt",
            "/sbin/veracrypt",
            "/usr/bin/veracrypt-console",
            "/usr/sbin/veracrypt-console"
        ];
        foreach ($testPaths as $path) {
            try {
                $proc = new \OMV\System\Process("test", ["-f", $path]);
                $proc->execute($output, $exitStatus);
                if ($exitStatus === 0) {
                    return true;
                }
            } catch (\Exception $e) {
                // ignore
            }
        }
        try {
            $proc = new \OMV\System\Process("sh", ["-c", "command -v veracrypt || which veracrypt || find /usr -name veracrypt -type f"]);
            $proc->execute($output, $exitStatus);
            if ($exitStatus === 0 && !empty($output)) {
                return true;
            }
        } catch (\Exception $e) {
            // ignore
        }
        try {
            $proc = new \OMV\System\Process("dpkg", ["-l"]);
            $proc->execute($output, $exitStatus);
            if ($exitStatus === 0) {
                foreach ($output as $line) {
                    if (preg_match('/^\s*ii\s+(veracrypt|veracrypt-console)\s/i', $line)) {
                        return true;
                    }
                }
            }
        } catch (\Exception $e) {
            // ignore
        }
        return false;
    }

    private function checkVeraCryptInstalled()
    {
        $installed = $this->isVeraCryptInstalled();
        $status = $installed ? "installed" : "removed";
        try {
            $db = \OMV\Config\Database::getInstance();
            $object = $this->getConfigObject();
            if ($object->get("installed") !== $status) {
                $object->set("installed", $status);
                $db->set($object);
            }
        } catch (\Exception $e) {
            // ignore
        }
        if (!$installed) {
            throw new \OMV\Exception("VeraCrypt is not installed on this system. Please go to the 'VeraCrypt Installer' tab to install it first.");
        }
    }

    private function parseActiveMountPoints($listOutput)
    {
        $activeMounts = [];
        foreach ($listOutput as $line) {
            $trimmedLine = trim($line);
            if (empty($trimmedLine) || stripos($trimmedLine, "no volumes") !== false || stripos($trimmedLine, "error") !== false) {
                continue;
            }

            // Extract mountpoint
            $parts = preg_split('/\s+/', $trimmedLine);
            $paths = [];
            foreach ($parts as $part) {
                if (strpos($part, '/') === 0 && strpos($part, '/dev/') !== 0) {
                    $paths[] = $part;
                }
            }
            if (!empty($paths)) {
                $mountpoint = $paths[count($paths) - 1];
                // Fallback: if we have "on /path", override mountpoint with that
                if (preg_match('/on\s+(\/\S+)/i', $line, $onMatches)) {
                    $mountpoint = $onMatches[1];
                }
                $activeMounts[] = $mountpoint;
            }
        }
        return array_unique($activeMounts);
    }

    public function getProfileList($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->logDebug("getProfileList() called with params: " . json_encode($params));

        $profilesList = [];
        try {
            $config = $this->getConfigObject();
            $profilesData = $config->get("profiles") ? $config->get("profiles") : [];
            if (isset($profilesData['profile'])) {
                $profilesList = $profilesData['profile'];
            }
        } catch (\Exception $e) {
            try {
                $cmd = new \OMV\System\Process("omv-confdbadm", ["create", "conf.service.veracrypt"]);
                $cmd->execute();
            } catch (\Exception $ex) {
                // ignore
            }
        }

        // Check if veracrypt is installed
        $installed = $this->isVeraCryptInstalled();

        // Get active mounts
        $activeMounts = [];
        if ($installed) {
            try {
                $cmdList = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
                $cmdList->setRedirect2to1();
                $cmdList->execute($listOutput, $listExitStatus);
                if ($listExitStatus === 0) {
                    $activeMounts = $this->parseActiveMountPoints($listOutput);
                }
            } catch (\Exception $e) {
                // Ignore exception if veracrypt -l exits with non-zero
            }
        }

        // Calculate mount state for each profile
        $resultList = [];
        foreach ($profilesList as $profile) {
            $containerLoc = isset($profile['container_location']) ? $profile['container_location'] : '';
            $endpoint = isset($profile['endpoint_folder']) ? $profile['endpoint_folder'] : '';
            $sfUuid = isset($profile['shared_folder_uuid']) ? $profile['shared_folder_uuid'] : '';

            if (!empty($sfUuid)) {
                try {
                    $sf = new \OMV\System\SharedFolder($sfUuid);
                    $basePath = $sf->getAbspath();
                    if (!empty($containerLoc)) {
                        $containerLoc = build_path(DIRECTORY_SEPARATOR, $basePath, $containerLoc);
                    } else {
                        $containerLoc = $basePath;
                    }
                } catch (\Exception $e) {
                    // fallback
                }
            }

            if (strpos($endpoint, '/') !== 0) {
                if (!empty($containerLoc)) {
                    $mountpoint = build_path(DIRECTORY_SEPARATOR, $containerLoc, $endpoint);
                } else {
                    $mountpoint = build_path(DIRECTORY_SEPARATOR, "/srv", $endpoint);
                }
            } else {
                $mountpoint = $endpoint;
            }

            $mounted = false;
            if (in_array($mountpoint, $activeMounts)) {
                $mounted = true;
            } else {
                $cmdMp = new \OMV\System\Process("mountpoint", ["-q", $mountpoint]);
                $cmdMp->execute($mpOutput, $mpExit);
                if ($mpExit === 0) {
                    $mounted = true;
                }
            }

            $profile['mounted'] = $mounted;
            $profile['installed'] = $installed;
            $profile['is_profile'] = true;
            $profile['is_virtual'] = false;
            $profile['mount_enabled'] = $installed;
            $profile['unmount_enabled'] = $installed;
            $profile['value'] = $profile['uuid'];
            $profile['label'] = $profile['name'];
            $resultList[] = $profile;
        }

        $this->logDebug("getProfileList() returning " . count($resultList) . " profiles.");
        return $resultList;
    }

    public function setProfile($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.setProfile");
        $this->logDebug("setProfile() called with params: " . json_encode($params));

        $uuid = $params['uuid'];
        if ($uuid === "00000000-0000-0000-0000-000000000000") {
            throw new \OMV\Exception("This is a system status indicator row and cannot be edited.");
        }

        $db = \OMV\Config\Database::getInstance();
        $profilesData = [];
        $profilesList = [];
        try {
            $object = $this->getConfigObject();
            $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
            if (isset($profilesData['profile'])) {
                $profilesList = $profilesData['profile'];
            }
        } catch (\Exception $e) {
            try {
                $cmd = new \OMV\System\Process("omv-confdbadm", ["create", "conf.service.veracrypt"]);
                $cmd->execute();
                $object = $this->getConfigObject();
                $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
                if (isset($profilesData['profile'])) {
                    $profilesList = $profilesData['profile'];
                }
            } catch (\Exception $ex) {
                // ignore
            }
        }

        // Handle profile modifications (if remember_configs is false, clear password)
        if (isset($params['remember_configs']) && !$params['remember_configs']) {
            $params['password'] = "";
        }

        $found = false;
        $oldPassword = "";

        foreach ($profilesList as $key => $p) {
            if ($p['uuid'] === $uuid) {
                $oldPassword = isset($p['password']) ? $p['password'] : '';
                break;
            }
        }

        $newPassword = isset($params['password']) ? $params['password'] : '';
        if ($newPassword !== $oldPassword) {
            if (isset($params['save_password']) && $params['save_password']) {
                if (!empty($newPassword)) {
                    $params['password'] = base64_encode($newPassword);
                }
            } else {
                $params['password'] = "";
            }
        } else {
            $params['password'] = $oldPassword;
        }

        $filteredParams = $this->filterProfileData($params);

        $found = false;
        foreach ($profilesList as $key => $p) {
            if ($p['uuid'] === $uuid) {
                $profilesList[$key] = $filteredParams;
                $found = true;
                break;
            }
        }

        if (!$found) {
            $profilesList[] = $filteredParams;
        }

        $profilesData['profile'] = $profilesList;
        $object->set("profiles", $profilesData);
        $db->set($object);

        $this->logDebug("setProfile() successfully saved and returning: " . json_encode($params));
        return $params;
    }

    public function deleteProfile($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.deleteProfile");

        $uuid = $params['uuid'];
        if ($uuid === "00000000-0000-0000-0000-000000000000") {
            throw new \OMV\Exception("This is a system status indicator row and cannot be deleted.");
        }

        $db = \OMV\Config\Database::getInstance();
        $profilesData = [];
        $profilesList = [];
        try {
            $object = $this->getConfigObject();
            $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
            if (isset($profilesData['profile'])) {
                $profilesList = $profilesData['profile'];
            }
        } catch (\Exception $e) {
            try {
                $cmd = new \OMV\System\Process("omv-confdbadm", ["create", "conf.service.veracrypt"]);
                $cmd->execute();
                $object = $this->getConfigObject();
                $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
                if (isset($profilesData['profile'])) {
                    $profilesList = $profilesData['profile'];
                }
            } catch (\Exception $ex) {
                // ignore
            }
        }

        $newProfilesList = [];

        foreach ($profilesList as $p) {
            if ($p['uuid'] !== $uuid) {
                $newProfilesList[] = $p;
            }
        }

        $profilesData['profile'] = $newProfilesList;
        $object->set("profiles", $newProfilesList);
        $db->set($object);

        return ["uuid" => $uuid, "success" => true];
    }

    public function createContainer($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.createContainer");
        $this->checkVeraCryptInstalled();

        $path = $params['path'];
        $sharedFolderUuid = isset($params['shared_folder_uuid']) ? $params['shared_folder_uuid'] : '';
        if (!empty($sharedFolderUuid)) {
            try {
                $sf = new \OMV\System\SharedFolder($sharedFolderUuid);
                $basePath = $sf->getAbspath();
                $path = build_path(DIRECTORY_SEPARATOR, $basePath, $path);
            } catch (\Exception $e) {
                // fallback
            }
        }

        $size = isset($params['size']) ? $params['size'] : '500M';
        $password = isset($params['password']) ? $params['password'] : '';
        $filesystem = isset($params['filesystem']) ? $params['filesystem'] : 'exFAT';
        $encryption = isset($params['encryption']) ? $params['encryption'] : 'AES';
        $hash = isset($params['hash']) ? $params['hash'] : 'sha-512';

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) use ($path, $size, $password, $filesystem, $encryption, $hash) {
            // Determine create arguments
            $args = [
                "-t",
                "--non-interactive",
                "--create",
                $path,
                "--size",
                $size,
                "--encryption",
                $encryption,
                "--hash",
                $hash,
                "--filesystem",
                $filesystem,
                "--password",
                $password,
                "--pim=0",
                "--keyfiles=",
                "--volume-type",
                "normal",
                "--random-source",
                "/dev/urandom"
            ];

            $cmd = new \OMV\System\Process("veracrypt", $args);
            $cmd->setRedirect2to1();
            $cmdLine = $cmd->getCommandLine();
            $exitStatus = $this->exec($cmdLine, $output, $bgOutputFilename);
            if (0 !== $exitStatus) {
                // If container file exists and is greater than 0 bytes, consider successful creation
                if (file_exists($path) && filesize($path) > 0) {
                    return $output;
                }
                throw new \OMV\ExecException($cmdLine, $output);
            }
            return $output;
        });
    }

    public function mount($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.mount");
        $this->checkVeraCryptInstalled();

        $uuid = $params['uuid'];
        $targetProfile = null;
        try {
            $config = $this->getConfigObject();
            $profiles = $config->get("profiles") ? $config->get("profiles") : [];
            if (isset($profiles['profile'])) {
                foreach ($profiles['profile'] as $p) {
                    if ($p['uuid'] === $uuid) {
                        $targetProfile = $p;
                        break;
                    }
                }
            }
        } catch (\Exception $e) {
            // ignore
        }

        if (!$targetProfile) {
            throw new \OMV\Exception("Profile not found.");
        }

        $type = isset($targetProfile['type']) ? $targetProfile['type'] : 'file';
        $containerLoc = isset($targetProfile['container_location']) ? $targetProfile['container_location'] : '';
        $endpoint = isset($targetProfile['endpoint_folder']) ? $targetProfile['endpoint_folder'] : '';

        $password = isset($params['password']) ? $params['password'] : '';
        if (empty($password)) {
            $password = isset($targetProfile['password']) ? $targetProfile['password'] : '';
            if (!empty($password)) {
                $decoded = base64_decode($password, true);
                if ($decoded !== false) {
                    $password = $decoded;
                }
            }
        }

        $perm = isset($targetProfile['permissions']) ? $targetProfile['permissions'] : '777';
        $sfUuid = isset($targetProfile['shared_folder_uuid']) ? $targetProfile['shared_folder_uuid'] : '';

        if (!empty($sfUuid)) {
            try {
                $sf = new \OMV\System\SharedFolder($sfUuid);
                $basePath = $sf->getAbspath();
                if (!empty($containerLoc)) {
                    $containerLoc = build_path(DIRECTORY_SEPARATOR, $basePath, $containerLoc);
                } else {
                    $containerLoc = $basePath;
                }
            } catch (\Exception $e) {
                // fallback
            }
        }

        // Prepare absolute paths
        // Check if endpoint is an absolute path or relative to a shared folder
        if (strpos($endpoint, '/') !== 0) {
            // Relative folder name, let's prefix with container_location if container_location is specified
            if (!empty($containerLoc)) {
                $mountpoint = build_path(DIRECTORY_SEPARATOR, $containerLoc, $endpoint);
            } else {
                $mountpoint = build_path(DIRECTORY_SEPARATOR, "/srv", $endpoint);
            }
        } else {
            $mountpoint = $endpoint;
        }

        if ($type === 'drive') {
            // For drive, container location represents device or partition name (e.g. sdc1), or absolute path
            $device = $containerLoc;
            if (strpos($device, '/dev/') !== 0 && !empty($device)) {
                $device = "/dev/" . $device;
            }
            $script = "/usr/sbin/vcd.sh";
            $args = [$device, $mountpoint, $password, $perm];
        } else {
            // For file, the container location is the full path of the container
            $containerPath = $containerLoc;
            $script = "/usr/sbin/vcm.sh";
            $args = [$containerPath, $mountpoint, $password, $perm];
        }

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) use ($script, $args) {
            $cmd = new \OMV\System\Process($script, $args);
            $cmd->setRedirect2to1();
            $cmdLine = $cmd->getCommandLine();
            $exitStatus = $this->exec($cmdLine, $output, $bgOutputFilename);
            if ($exitStatus !== 0) {
                throw new \OMV\ExecException($cmdLine, $output);
            }
            return $output;
        });
    }

    public function mountManual($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.mountManual");
        $this->checkVeraCryptInstalled();

        $type = isset($params['type']) ? $params['type'] : 'file';
        $containerLoc = isset($params['container_location']) ? $params['container_location'] : '';
        $endpoint = isset($params['endpoint_folder']) ? $params['endpoint_folder'] : '';
        $password = isset($params['password']) ? $params['password'] : '';
        $perm = isset($params['permissions']) ? $params['permissions'] : '777';
        $sfUuid = isset($params['shared_folder_uuid']) ? $params['shared_folder_uuid'] : '';

        if (!empty($sfUuid)) {
            try {
                $sf = new \OMV\System\SharedFolder($sfUuid);
                $basePath = $sf->getAbspath();
                if (!empty($containerLoc)) {
                    $containerLoc = build_path(DIRECTORY_SEPARATOR, $basePath, $containerLoc);
                } else {
                    $containerLoc = $basePath;
                }
            } catch (\Exception $e) {
                // fallback
            }
        }

        // Prepare absolute paths
        if (strpos($endpoint, '/') !== 0) {
            if (!empty($containerLoc)) {
                $mountpoint = build_path(DIRECTORY_SEPARATOR, $containerLoc, $endpoint);
            } else {
                $mountpoint = build_path(DIRECTORY_SEPARATOR, "/srv", $endpoint);
            }
        } else {
            $mountpoint = $endpoint;
        }

        if ($type === 'drive') {
            $device = $containerLoc;
            if (strpos($device, '/dev/') !== 0 && !empty($device)) {
                $device = "/dev/" . $device;
            }
            $script = "/usr/sbin/vcd.sh";
            $args = [$device, $mountpoint, $password, $perm];
        } else {
            $containerPath = $containerLoc;
            $script = "/usr/sbin/vcm.sh";
            $args = [$containerPath, $mountpoint, $password, $perm];
        }

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) use ($script, $args) {
            $cmd = new \OMV\System\Process($script, $args);
            $cmd->setRedirect2to1();
            $cmdLine = $cmd->getCommandLine();
            $exitStatus = $this->exec($cmdLine, $output, $bgOutputFilename);
            if ($exitStatus !== 0) {
                throw new \OMV\ExecException($cmdLine, $output);
            }
            return $output;
        });
    }

    public function getProfileDetails($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.getProfileDetails");
        $this->logDebug("getProfileDetails() called with params: " . json_encode($params));

        $installed = $this->isVeraCryptInstalled();
        $uuid = isset($params['uuid']) ? $params['uuid'] : '';

        // Ensure a valid UUIDv4 is generated if empty, new, or invalid
        if (empty($uuid) || $uuid === "new" || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid)) {
            $uuid = $this->generateUuid4();
        }

        $profile = [
            "installed" => $installed,
            "installed_str" => $installed ? "yes" : "no",
            "vc_installed_status" => $installed ? "🟢 VeraCrypt installed" : "🔴 Please Install VeraCrypt!",
            "vc_not_installed_status" => "🔴 Please Install VeraCrypt!",
            "uuid" => $uuid,
            "name" => "",
            "type" => "file",
            "shared_folder_uuid" => "",
            "container_location" => "",
            "endpoint_folder" => "",
            "password" => "",
            "permissions" => "777",
            "save_password" => false
        ];

        if (isset($params['uuid']) && !empty($params['uuid']) && $params['uuid'] !== "new") {
            $passedUuid = $params['uuid'];
            try {
                $config = $this->getConfigObject();
                $profiles = $config->get("profiles") ? $config->get("profiles") : [];
                if (isset($profiles['profile'])) {
                    foreach ($profiles['profile'] as $p) {
                        if ($p['uuid'] === $passedUuid) {
                            foreach ($p as $key => $val) {
                                if ($key !== "filename" && $key !== "remember_configs") {
                                    $profile[$key] = $val;
                                }
                            }
                            $profile['uuid'] = $passedUuid;
                            break;
                        }
                    }
                }
            } catch (\Exception $e) {
                // ignore
            }
        }

        $this->logDebug("getProfileDetails() returning profile: " . json_encode($profile));
        return $profile;
    }

    public function unmount($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.unmount");
        $this->checkVeraCryptInstalled();

        $uuid = isset($params['uuid']) ? $params['uuid'] : '';
        $endpoint = isset($params['endpoint_folder']) ? $params['endpoint_folder'] : '';
        $sfUuid = '';
        $containerLoc = '';

        if (!empty($uuid)) {
            $targetProfile = null;
            try {
                $config = $this->getConfigObject();
                $profiles = $config->get("profiles") ? $config->get("profiles") : [];
                if (isset($profiles['profile'])) {
                    foreach ($profiles['profile'] as $p) {
                        if ($p['uuid'] === $uuid) {
                            $targetProfile = $p;
                            break;
                        }
                    }
                }
            } catch (\Exception $e) {
                // ignore
            }

            if ($targetProfile) {
                $containerLoc = isset($targetProfile['container_location']) ? $targetProfile['container_location'] : '';
                $endpoint = isset($targetProfile['endpoint_folder']) ? $targetProfile['endpoint_folder'] : '';
                $sfUuid = isset($targetProfile['shared_folder_uuid']) ? $targetProfile['shared_folder_uuid'] : '';
            }
        }

        if (!empty($sfUuid)) {
            try {
                $sf = new \OMV\System\SharedFolder($sfUuid);
                $basePath = $sf->getAbspath();
                if (!empty($containerLoc)) {
                    $containerLoc = build_path(DIRECTORY_SEPARATOR, $basePath, $containerLoc);
                } else {
                    $containerLoc = $basePath;
                }
            } catch (\Exception $e) {
                // fallback
            }
        }

        if (strpos($endpoint, '/') !== 0) {
            if (!empty($containerLoc)) {
                $mountpoint = build_path(DIRECTORY_SEPARATOR, $containerLoc, $endpoint);
            } else {
                $mountpoint = build_path(DIRECTORY_SEPARATOR, "/srv", $endpoint);
            }
        } else {
            $mountpoint = $endpoint;
        }

        $script = "/usr/sbin/vcu.sh";
        $args = [$mountpoint];

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) use ($script, $args) {
            $cmd = new \OMV\System\Process($script, $args);
            $cmd->setRedirect2to1();
            $cmdLine = $cmd->getCommandLine();
            $exitStatus = $this->exec($cmdLine, $output, $bgOutputFilename);
            if ($exitStatus !== 0) {
                throw new \OMV\ExecException($cmdLine, $output);
            }
            return $output;
        });
    }

    public function installVeraCrypt($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) {
            // Run helper installer script
            $cmd = new \OMV\System\Process("sh", [
                "/usr/sbin/vci.sh"
            ]);
            $cmd->setRedirect2to1();
            $cmdLine = $cmd->getCommandLine();
            if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename)) {
                throw new \OMV\ExecException($cmdLine, $output);
            }

            try {
                $db = \OMV\Config\Database::getInstance();
                $object = $this->getConfigObject();
                $object->set("installed", "installed");
                $db->set($object);
            } catch (\Exception $e) {
                // ignore
            }

            return $output;
        });
    }

    public function removeVeraCrypt($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) {
            $cmd = new \OMV\System\Process("sh", [
                "-c",
                "export DEBIAN_FRONTEND=noninteractive; apt-get purge -y veracrypt-console veracrypt || echo 'VeraCrypt removal completed.'"
            ]);
            $cmd->setRedirect2to1();
            $cmdLine = $cmd->getCommandLine();
            if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename)) {
                throw new \OMV\ExecException($cmdLine, $output);
            }

            try {
                $db = \OMV\Config\Database::getInstance();
                $object = $this->getConfigObject();
                $object->set("installed", "removed");
                $db->set($object);
            } catch (\Exception $e) {
                // ignore
            }

            return $output;
        });
    }

    public function checkInstall($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) {
            echo "Checking if VeraCrypt is installed on this system...\n";
            $installed = $this->isVeraCryptInstalled();
            $status = $installed ? "installed" : "removed";

            try {
                $db = \OMV\Config\Database::getInstance();
                $object = $this->getConfigObject();
                $object->set("installed", $status);
                $db->set($object);
            } catch (\Exception $e) {
                // ignore
            }

            if ($installed) {
                echo "SUCCESS: VeraCrypt is installed! (Saved status as 'installed')\n";
            } else {
                echo "FAILED: VeraCrypt is NOT installed! (Saved status as 'removed')\n";
            }
        });
    }

    public function listMountedVolumes($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->checkVeraCryptInstalled();

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) {
            try {
                $volumes = $this->getMountedVolumes([], null);
                if (empty($volumes)) {
                    file_put_contents($bgOutputFilename, "No VeraCrypt volumes are currently mounted.\n", FILE_APPEND);
                } else {
                    file_put_contents($bgOutputFilename, "Currently mounted VeraCrypt folders:\n", FILE_APPEND);
                    foreach ($volumes as $vol) {
                        file_put_contents($bgOutputFilename, " - Slot " . $vol['slot'] . ": " . $vol['mountpoint'] . " (Container: " . $vol['container'] . ")\n", FILE_APPEND);
                    }
                }
            } catch (\Exception $e) {
                file_put_contents($bgOutputFilename, "ERROR: " . $e->getMessage() . "\n", FILE_APPEND);
            }
        });
    }

    public function getStatus($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.getStatus");
        $this->logDebug("getStatus() called with params: " . json_encode($params));

        // 1. Check if VeraCrypt is installed
        $installed = $this->isVeraCryptInstalled();


        // 2. Check mount status of the profile if uuid is provided, or list active mounts
        $mounted = false;
        $activeMounts = [];

        if ($installed) {
            try {
                $cmdList = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
                $cmdList->setRedirect2to1();
                $cmdList->execute($listOutput, $listExitStatus);
                if ($listExitStatus === 0) {
                    $activeMounts = $this->parseActiveMountPoints($listOutput);
                }
            } catch (\Exception $e) {
                // Ignore exception if veracrypt -l exits with non-zero
            }
        }

        if (isset($params['uuid']) && !empty($params['uuid'])) {
            $uuid = $params['uuid'];
            $targetProfile = null;
            try {
                $config = $this->getConfigObject();
                $profiles = $config->get("profiles") ? $config->get("profiles") : [];
                if (isset($profiles['profile'])) {
                    foreach ($profiles['profile'] as $p) {
                        if ($p['uuid'] === $uuid) {
                            $targetProfile = $p;
                            break;
                        }
                    }
                }
            } catch (\Exception $e) {
                // ignore
            }

            if ($targetProfile) {
                $containerLoc = isset($targetProfile['container_location']) ? $targetProfile['container_location'] : '';
                $endpoint = isset($targetProfile['endpoint_folder']) ? $targetProfile['endpoint_folder'] : '';

                if (strpos($endpoint, '/') !== 0) {
                    if (!empty($containerLoc)) {
                        $mountpoint = build_path(DIRECTORY_SEPARATOR, $containerLoc, $endpoint);
                    } else {
                        $mountpoint = build_path(DIRECTORY_SEPARATOR, "/srv", $endpoint);
                    }
                } else {
                    $mountpoint = $endpoint;
                }

                // Check if mountpoint is in the active mounts list or if it's currently mounted (via df or /proc/mounts)
                if (in_array($mountpoint, $activeMounts)) {
                    $mounted = true;
                } else {
                    // Fallback to reading /proc/mounts or running mountpoint command
                    $cmdMp = new \OMV\System\Process("mountpoint", ["-q", $mountpoint]);
                    $cmdMp->execute($mpOutput, $mpExit);
                    if ($mpExit === 0) {
                        $mounted = true;
                    }
                }
            }
        }

        $activeMountsCount = count($activeMounts);
        if (!$installed) {
            $activeMountsStatus = "🔴 VeraCrypt is NOT installed";
        } elseif ($activeMountsCount > 0) {
            $activeMountsStatus = sprintf("🟢 %d Active VeraCrypt Mount(s) Detected", $activeMountsCount);
        } else {
            $activeMountsStatus = "⚪ No active VeraCrypt mounts detected";
        }

        $mountedTextLines = [];
        if ($installed) {
            $volumes = $this->getMountedVolumes([], null);
            foreach ($volumes as $v) {
                $mountedTextLines[] = " - " . $v['mountpoint'] . " (Slot " . $v['slot'] . ")";
            }
        }
        $mountedVolumesText = !empty($mountedTextLines)
            ? implode("\n", $mountedTextLines)
            : "No active VeraCrypt volumes mounted.";

        $response = [
            "installed" => $installed,
            "installed_str" => $installed ? "yes" : "no",
            "mounted" => $mounted,
            "active_mounts" => $activeMounts,
            "active_mounts_status" => $activeMountsStatus,
            "mounted_volumes_text" => $mountedVolumesText,
            "mounted_volumes" => [],
            "vc_installed_status" => $installed ? "🟢 VeraCrypt installed" : "🔴 Please Install VeraCrypt!",
            "vc_not_installed_status" => "🔴 Please Install VeraCrypt!",
            "vc_bottom_notice" => "🔴 VeraCrypt is NOT installed. Please install veracrypt to enable this."
        ];
        $this->logDebug("getStatus() returning: " . json_encode($response));
        return $response;
    }

    public function getMountedVolumes($params, $context)
    {
        if ($context !== null) {
            $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
            $this->validateMethodParams($params, "rpc.veracrypt.getMountedVolumes");
        }
        $this->checkVeraCryptInstalled();

        $volumes = [];
        $seenMountpoints = [];
        $output = [];

        try {
            $cmd = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
            $cmd->setRedirect2to1();
            $cmd->execute($output, $exitStatus);
            if (!empty($output)) {
                foreach ($output as $line) {
                    $trimmedLine = trim($line);
                    if (empty($trimmedLine) || stripos($trimmedLine, "no volumes") !== false || stripos($trimmedLine, "error") !== false) {
                        continue;
                    }

                    // Extract slot
                    $slot = "1";
                    if (preg_match('/^(Slot\s+)?(\d+)[:.]\s*/i', $trimmedLine, $slotMatches)) {
                        $slot = $slotMatches[2];
                        $trimmedLine = substr($trimmedLine, strlen($slotMatches[0]));
                    }

                    $parts = preg_split('/\s+/', $trimmedLine);
                    $paths = [];
                    $device = "";
                    foreach ($parts as $part) {
                        if (strpos($part, '/') === 0) {
                            if (strpos($part, '/dev/') === 0) {
                                $device = $part;
                            } else {
                                $paths[] = $part;
                            }
                        }
                    }

                    if (!empty($paths)) {
                        if (count($paths) >= 2) {
                            $container = $paths[0];
                            $mountpoint = $paths[count($paths) - 1];
                        } else {
                            $container = $paths[0];
                            $mountpoint = $paths[0];
                        }

                        if (preg_match('/on\s+(\/\S+)/i', $line, $onMatches)) {
                            $mountpoint = $onMatches[1];
                        }

                        $volumes[] = [
                            "id" => $mountpoint,
                            "slot" => $slot,
                            "container" => $container,
                            "device" => $device,
                            "mountpoint" => $mountpoint
                        ];
                        $seenMountpoints[$mountpoint] = true;
                    }
                }
            }
        } catch (\Exception $e) {
            // ignore error
        }

        // Safety net: ensure any mountpoint extracted by parseActiveMountPoints is included
        if (!empty($output)) {
            $parsedPoints = $this->parseActiveMountPoints($output);
            foreach ($parsedPoints as $idx => $mp) {
                if (!isset($seenMountpoints[$mp])) {
                    $volumes[] = [
                        "id" => $mp,
                        "slot" => (string)($idx + 1),
                        "container" => $mp,
                        "device" => "",
                        "mountpoint" => $mp
                    ];
                    $seenMountpoints[$mp] = true;
                }
            }
        }

        // Supplementary fallback via /proc/mounts
        if (file_exists('/proc/mounts') && is_readable('/proc/mounts')) {
            $mountLines = file('/proc/mounts', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($mountLines)) {
                $vcIndex = 1;
                foreach ($mountLines as $mLine) {
                    if (preg_match('/^(\/dev\/mapper\/veracrypt\d+)\s+(\/\S+)\s+/i', trim($mLine), $mMatches)) {
                        $dev = $mMatches[1];
                        $mp = $mMatches[2];
                        if (!isset($seenMountpoints[$mp])) {
                            $volumes[] = [
                                "id" => $mp,
                                "slot" => (string)$vcIndex,
                                "container" => $dev,
                                "device" => $dev,
                                "mountpoint" => $mp
                            ];
                            $seenMountpoints[$mp] = true;
                            $vcIndex++;
                        }
                    }
                }
            }
        }

        return $volumes;
    }

    public function getMountedVolumesList($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.getMountedVolumesList");
        $this->checkVeraCryptInstalled();

        $volumes = [];
        $mounted = $this->getMountedVolumes([], null);
        foreach ($mounted as $vol) {
            $label = $vol['mountpoint'];
            if (!empty($vol['slot'])) {
                $label .= " (Slot " . $vol['slot'] . ")";
            }
            $volumes[] = [
                "value" => $vol['mountpoint'],
                "label" => $label,
                "id" => $vol['mountpoint'],
                "name" => $label,
                0 => $vol['mountpoint'],
                1 => $label
            ];
        }
        return $volumes;
    }

    public function unmountAll($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.unmountAll");
        $this->checkVeraCryptInstalled();

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) {
            $cmd = new \OMV\System\Process("veracrypt", ["-t", "-u"]);
            $cmd->setRedirect2to1();
            $cmdLine = $cmd->getCommandLine();
            $exitStatus = $this->exec($cmdLine, $output, $bgOutputFilename);
            if ($exitStatus !== 0) {
                throw new \OMV\ExecException($cmdLine, $output);
            }
            return $output;
        });
    }

    public function unmountMultiple($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.unmountMultiple");
        $this->checkVeraCryptInstalled();

        $rawInputs = isset($params['mounted_volumes']) ? $params['mounted_volumes'] : [];

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) use ($rawInputs) {
            // Get currently mounted volumes to map slot numbers to mountpoints
            $activeVolumes = $this->getMountedVolumes([], null);
            $slotMap = [];
            foreach ($activeVolumes as $vol) {
                if (isset($vol['slot']) && isset($vol['mountpoint'])) {
                    $slotMap[(string)$vol['slot']] = $vol['mountpoint'];
                }
            }

            $targetPaths = [];

            foreach ($rawInputs as $raw) {
                if (empty($raw)) {
                    continue;
                }
                $rawTrimmed = trim((string)$raw);
                if (empty($rawTrimmed)) {
                    continue;
                }

                // Check if absolute filesystem path
                if (strpos($rawTrimmed, '/') === 0) {
                    $targetPaths[] = $rawTrimmed;
                    continue;
                }

                // Handle slot numbers and flexible formats (e.g. "1", "1,2", "[1 2 3]", "1&3", "[1,2]")
                // Extract digits/numbers from string
                if (preg_match_all('/\d+/', $rawTrimmed, $digitMatches)) {
                    foreach ($digitMatches[0] as $slotNum) {
                        if (isset($slotMap[$slotNum])) {
                            $targetPaths[] = $slotMap[$slotNum];
                        }
                    }
                }
            }

            $targetPaths = array_unique($targetPaths);

            if (empty($targetPaths)) {
                file_put_contents($bgOutputFilename, "No valid mounted targets found to unmount.\n", FILE_APPEND);
                return ["No valid mounted targets found to unmount."];
            }

            $script = "/usr/sbin/vcu.sh";
            $output = [];
            foreach ($targetPaths as $mp) {
                if (empty($mp)) {
                    continue;
                }
                $cmd = new \OMV\System\Process($script, [$mp]);
                $cmd->setRedirect2to1();
                $cmd->execute($cmdOutput, $exitStatus);
                if (is_array($cmdOutput)) {
                    foreach ($cmdOutput as $line) {
                        file_put_contents($bgOutputFilename, $line . "\n", FILE_APPEND);
                    }
                    $output = array_merge($output, $cmdOutput);
                }
            }
            return $output;
        });
    }
}
