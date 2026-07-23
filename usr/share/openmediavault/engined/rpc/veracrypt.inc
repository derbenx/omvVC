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
        $paths = [
            "/usr/bin/veracrypt",
            "/usr/sbin/veracrypt",
            "/usr/local/bin/veracrypt",
            "/bin/veracrypt",
            "/sbin/veracrypt",
            "/usr/bin/veracrypt-console",
            "/usr/sbin/veracrypt-console"
        ];
        foreach ($paths as $path) {
            if (@file_exists($path)) {
                return true;
            }
        }
        try {
            $proc = new \OMV\System\Process("sh", ["-c", "command -v veracrypt || which veracrypt"]);
            $proc->execute($output, $exitStatus);
            if ($exitStatus === 0 && !empty($output)) {
                return true;
            }
        } catch (\Exception $e) {
            // ignore
        }
        try {
            $proc = new \OMV\System\Process("veracrypt", ["-t", "--version"]);
            $proc->execute($output, $exitStatus);
            if ($exitStatus === 0 || $exitStatus === 1) {
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
        if (!$this->isVeraCryptInstalled()) {
            throw new \OMV\Exception("VeraCrypt is not installed on this system. Please go to the 'VeraCrypt Installer' tab to install it first.");
        }
    }

    public function getProfileList($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);

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
                $cmdList->execute($listOutput, $listExitStatus);
                if ($listExitStatus === 0) {
                    foreach ($listOutput as $line) {
                        if (preg_match('/on\s+(.+)$/', $line, $matches)) {
                            $activeMounts[] = trim($matches[1]);
                        }
                    }
                }
            } catch (\Exception $e) {
                // Ignore exception if veracrypt -l exits with non-zero (meaning no volumes are mounted)
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
            $resultList[] = $profile;
        }

        // Prepend virtual status row
        $statusRow = [
            "uuid" => "00000000-0000-0000-0000-000000000000",
            "name" => $installed ? "🟢 VeraCrypt is installed" : "🔴 VeraCrypt is NOT installed! Please install VeraCrypt from the Installer tab.",
            "type" => $installed ? "Installed" : "NOT Installed",
            "container_location" => "Please check the Installer tab to install or purge.",
            "filename" => "",
            "endpoint_folder" => "",
            "permissions" => "",
            "remember_configs" => false,
            "mounted" => $installed,
            "installed" => $installed,
            "is_profile" => false,
            "is_virtual" => true,
            "mount_enabled" => false,
            "unmount_enabled" => false
        ];
        array_unshift($resultList, $statusRow);

        return $resultList;
    }

    public function setProfile($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.setProfile");

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

        $installed = $this->isVeraCryptInstalled();
        $uuid = isset($params['uuid']) ? $params['uuid'] : '';

        // Ensure a valid UUIDv4 is generated if empty, new, or invalid
        if (empty($uuid) || $uuid === "new" || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid)) {
            $uuid = $this->generateUuid4();
        }

        $profile = [
            "installed" => $installed,
            "installed_str" => $installed ? "yes" : "no",
            "vc_installed_status" => "🟢 VeraCrypt installed",
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
            return $output;
        });
    }

    public function getStatus($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.getStatus");

        // 1. Check if VeraCrypt is installed
        $installed = $this->isVeraCryptInstalled();

        // Diagnostic debug info logging to syslog
        try {
            $debug = [];
            $debug['user'] = get_current_user();
            if (function_exists('posix_getuid')) {
                $debug['uid'] = posix_getuid();
            }
            $debug['open_basedir'] = ini_get('open_basedir');
            $debug['path_env'] = getenv('PATH');

            $paths = [
                "/usr/bin/veracrypt",
                "/usr/sbin/veracrypt",
                "/usr/local/bin/veracrypt",
                "/bin/veracrypt",
                "/sbin/veracrypt",
                "/usr/bin/veracrypt-console",
                "/usr/sbin/veracrypt-console"
            ];
            foreach ($paths as $path) {
                $debug["path_{$path}"] = @file_exists($path) ? "exists" : "not-found";
            }

            try {
                $proc = new \OMV\System\Process("sh", ["-c", "command -v veracrypt || which veracrypt"]);
                $proc->execute($shOutput, $shExit);
                $debug['sh_which'] = "exit={$shExit}, output=" . implode("\n", $shOutput);
            } catch (\Exception $e) {
                $debug['sh_which'] = "exception=" . $e->getMessage();
            }

            try {
                $proc = new \OMV\System\Process("veracrypt", ["-t", "--version"]);
                $proc->execute($vcOutput, $vcExit);
                $debug['veracrypt_version'] = "exit={$vcExit}, output=" . implode("\n", $vcOutput);
            } catch (\Exception $e) {
                $debug['veracrypt_version'] = "exception=" . $e->getMessage();
            }

            try {
                $proc = new \OMV\System\Process("dpkg", ["-l"]);
                $proc->execute($dpkgOutput, $dpkgExit);
                $pkgs = [];
                if ($dpkgExit === 0) {
                    foreach ($dpkgOutput as $line) {
                        if (preg_match('/veracrypt/i', $line)) {
                            $pkgs[] = $line;
                        }
                    }
                }
                $debug['dpkg_veracrypt'] = "exit={$dpkgExit}, pkgs=" . implode("\n", $pkgs);
            } catch (\Exception $e) {
                $debug['dpkg_veracrypt'] = "exception=" . $e->getMessage();
            }

            openlog("openmediavault-veracrypt", LOG_ODELAY | LOG_PID, LOG_USER);
            syslog(LOG_INFO, "Diagnostic Debug Info: " . json_encode($debug));
            closelog();
        } catch (\Exception $ex) {
            // ignore debug errors
        }

        // 2. Check mount status of the profile if uuid is provided, or list active mounts
        $mounted = false;
        $activeMounts = [];

        if ($installed) {
            try {
                $cmdList = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
                $cmdList->execute($listOutput, $listExitStatus);
                if ($listExitStatus === 0) {
                    foreach ($listOutput as $line) {
                        if (preg_match('/on\s+(.+)$/', $line, $matches)) {
                            $activeMounts[] = trim($matches[1]);
                        }
                    }
                }
            } catch (\Exception $e) {
                // Ignore exception if veracrypt -l exits with non-zero (meaning no volumes are mounted)
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

        return [
            "installed" => $installed,
            "installed_str" => $installed ? "yes" : "no",
            "mounted" => $mounted,
            "active_mounts" => $activeMounts,
            "vc_installed_status" => $installed ? "🟢 VeraCrypt installed" : "🔴 Please Install VeraCrypt!",
            "vc_not_installed_status" => "🔴 Please Install VeraCrypt!",
            "vc_bottom_notice" => "🔴 VeraCrypt is NOT installed. Please install veracrypt to enable this."
        ];
    }

    public function getMountedVolumes($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.getMountedVolumes");

        $volumes = [];
        if (!$this->isVeraCryptInstalled()) {
            return $volumes;
        }

        try {
            $cmd = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
            $cmd->execute($output, $exitStatus);
            if ($exitStatus === 0) {
                foreach ($output as $line) {
                    $trimmedLine = trim($line);
                    if (empty($trimmedLine)) {
                        continue;
                    }
                    // Pattern standard: "1: /path/to/container /dev/loopX /path/to/mountpoint"
                    if (preg_match('/^(\d+):\s+(.+?)\s+(\S+)\s+(.+)$/', $trimmedLine, $matches)) {
                        $volumes[] = [
                            "id" => $matches[1],
                            "slot" => $matches[1],
                            "container" => trim($matches[2]),
                            "device" => trim($matches[3]),
                            "mountpoint" => trim($matches[4])
                        ];
                    } else if (preg_match('/^(\d+):\s+(.+?)\s+(.+)$/', $trimmedLine, $matches)) {
                        $volumes[] = [
                            "id" => $matches[1],
                            "slot" => $matches[1],
                            "container" => trim($matches[2]),
                            "device" => "",
                            "mountpoint" => trim($matches[3])
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            // ignore error
        }

        return $volumes;
    }

    public function getMountedVolumesList($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.getMountedVolumesList");

        $volumes = [];
        if (!$this->isVeraCryptInstalled()) {
            return $volumes;
        }

        try {
            $cmd = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
            $cmd->execute($output, $exitStatus);
            if ($exitStatus === 0) {
                foreach ($output as $line) {
                    $trimmedLine = trim($line);
                    if (empty($trimmedLine)) {
                        continue;
                    }
                    if (preg_match('/^(\d+):\s+(.+?)\s+(\S+)\s+(.+)$/', $trimmedLine, $matches)) {
                        $container = trim($matches[2]);
                        $mountpoint = trim($matches[4]);
                        $volumes[] = [
                            "id" => $mountpoint,
                            "name" => "Slot {$matches[1]}: {$container} on {$mountpoint}",
                            "value" => $mountpoint,
                            "label" => "Slot {$matches[1]}: {$container} on {$mountpoint}"
                        ];
                    } else if (preg_match('/^(\d+):\s+(.+?)\s+(.+)$/', $trimmedLine, $matches)) {
                        $container = trim($matches[2]);
                        $mountpoint = trim($matches[3]);
                        $volumes[] = [
                            "id" => $mountpoint,
                            "name" => "Slot {$matches[1]}: {$container} on {$mountpoint}",
                            "value" => $mountpoint,
                            "label" => "Slot {$matches[1]}: {$container} on {$mountpoint}"
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            // ignore
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

        $mountpoints = isset($params['mounted_volumes']) ? $params['mounted_volumes'] : [];

        return $this->execBgProc(function($bgStatusFilename, $bgOutputFilename) use ($mountpoints) {
            $script = "/usr/sbin/vcu.sh";
            $output = [];
            foreach ($mountpoints as $mp) {
                if (empty($mp)) {
                    continue;
                }
                $cmd = new \OMV\System\Process($script, [$mp]);
                $cmd->execute($cmdOutput, $exitStatus);
                $output = array_merge($output, $cmdOutput);
            }
            return $output;
        });
    }
}
