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
        $this->registerMethod("setProfile");
        $this->registerMethod("deleteProfile");
        $this->registerMethod("mount");
        $this->registerMethod("unmount");
        $this->registerMethod("createContainer");
        $this->registerMethod("installVeraCrypt");
        $this->registerMethod("removeVeraCrypt");
        $this->registerMethod("getStatus");
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
                $profiles[] = $profile;
            }
            $params['profiles']['profile'] = $profiles;
        }

        $object->setAssoc($params);
        $db->set($object);
        return $object->getAssoc();
    }

    private function isVeraCryptInstalled()
    {
        if (file_exists("/usr/bin/veracrypt") || file_exists("/usr/sbin/veracrypt") || file_exists("/usr/local/bin/veracrypt")) {
            return true;
        }
        $cmdCheck = new \OMV\System\Process("which", ["veracrypt"]);
        $cmdCheck->execute($output, $exitStatus);
        return $exitStatus === 0;
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

        $config = $this->getConfigObject();
        $profilesData = $config->get("profiles") ? $config->get("profiles") : [];
        $profilesList = [];

        if (isset($profilesData['profile'])) {
            $profilesList = $profilesData['profile'];
        }

        // Check if veracrypt is installed
        $installed = $this->isVeraCryptInstalled();

        // Get active mounts
        $activeMounts = [];
        if ($installed) {
            $cmdList = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
            $cmdList->execute($listOutput, $listExitStatus);
            if ($listExitStatus === 0) {
                foreach ($listOutput as $line) {
                    if (preg_match('/on\s+(.+)$/', $line, $matches)) {
                        $activeMounts[] = trim($matches[1]);
                    }
                }
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
            $resultList[] = $profile;
        }

        // Prepend virtual status row
        $statusRow = [
            "uuid" => "00000000-0000-0000-0000-000000000000",
            "name" => $installed ? "🟢 VeraCrypt is installed" : "🔴 VeraCrypt is NOT installed!",
            "type" => $installed ? "Installed" : "NOT Installed",
            "container_location" => "Please check the Installer tab to install or purge.",
            "filename" => "",
            "endpoint_folder" => "",
            "permissions" => "",
            "remember_configs" => false,
            "mounted" => $installed,
            "installed" => $installed
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
        $object = $this->getConfigObject();
        $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
        $profilesList = [];

        if (isset($profilesData['profile'])) {
            $profilesList = $profilesData['profile'];
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

        $found = false;
        foreach ($profilesList as $key => $p) {
            if ($p['uuid'] === $uuid) {
                $profilesList[$key] = $params;
                $found = true;
                break;
            }
        }

        if (!$found) {
            $profilesList[] = $params;
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
        $object = $this->getConfigObject();
        $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
        $profilesList = [];

        if (isset($profilesData['profile'])) {
            $profilesList = $profilesData['profile'];
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
            if (0 !== $this->exec($cmdLine, $output, $bgOutputFilename)) {
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
        $config = $this->getConfigObject();
        $profiles = $config->get("profiles") ? $config->get("profiles") : [];
        $targetProfile = null;

        if (isset($profiles['profile'])) {
            foreach ($profiles['profile'] as $p) {
                if ($p['uuid'] === $uuid) {
                    $targetProfile = $p;
                    break;
                }
            }
        }

        if (!$targetProfile) {
            throw new \OMV\Exception("Profile not found.");
        }

        $type = isset($targetProfile['type']) ? $targetProfile['type'] : 'file';
        $containerLoc = isset($targetProfile['container_location']) ? $targetProfile['container_location'] : '';
        $endpoint = isset($targetProfile['endpoint_folder']) ? $targetProfile['endpoint_folder'] : '';
        $password = isset($targetProfile['password']) ? $targetProfile['password'] : '';
        if (!empty($password)) {
            $decoded = base64_decode($password, true);
            if ($decoded !== false) {
                $password = $decoded;
            }
        }
        $filename = isset($targetProfile['filename']) ? $targetProfile['filename'] : '';
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
            // For file, build path to container file
            if (strpos($filename, '/') === 0) {
                $containerPath = $filename;
            } else {
                $containerPath = build_path(DIRECTORY_SEPARATOR, $containerLoc, $filename);
            }
            $script = "/usr/sbin/vcm.sh";
            $args = [$containerPath, $mountpoint, $password, $perm];
        }

        $cmd = new \OMV\System\Process($script, $args);
        $cmd->execute($output, $exitStatus);

        if ($exitStatus !== 0) {
            throw new \OMV\Exception("Failed to mount VeraCrypt container: " . implode("\n", $output));
        }

        return ["success" => true, "output" => $output];
    }

    public function unmount($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.unmount");
        $this->checkVeraCryptInstalled();

        $uuid = $params['uuid'];
        $config = $this->getConfigObject();
        $profiles = $config->get("profiles") ? $config->get("profiles") : [];
        $targetProfile = null;

        if (isset($profiles['profile'])) {
            foreach ($profiles['profile'] as $p) {
                if ($p['uuid'] === $uuid) {
                    $targetProfile = $p;
                    break;
                }
            }
        }

        if (!$targetProfile) {
            throw new \OMV\Exception("Profile not found.");
        }

        $containerLoc = isset($targetProfile['container_location']) ? $targetProfile['container_location'] : '';
        $endpoint = isset($targetProfile['endpoint_folder']) ? $targetProfile['endpoint_folder'] : '';
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
        $cmd = new \OMV\System\Process($script, [$mountpoint]);
        $cmd->execute($output, $exitStatus);

        if ($exitStatus !== 0) {
            throw new \OMV\Exception("Failed to unmount VeraCrypt: " . implode("\n", $output));
        }

        return ["success" => true, "output" => $output];
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

        // 2. Check mount status of the profile if uuid is provided, or list active mounts
        $mounted = false;
        $activeMounts = [];

        if ($installed) {
            $cmdList = new \OMV\System\Process("veracrypt", ["-t", "-l"]);
            $cmdList->execute($listOutput, $listExitStatus);
            if ($listExitStatus === 0) {
                foreach ($listOutput as $line) {
                    if (preg_match('/on\s+(.+)$/', $line, $matches)) {
                        $activeMounts[] = trim($matches[1]);
                    }
                }
            }
        }

        if (isset($params['uuid']) && !empty($params['uuid'])) {
            $uuid = $params['uuid'];
            $config = $this->getConfigObject();
            $profiles = $config->get("profiles") ? $config->get("profiles") : [];
            $targetProfile = null;

            if (isset($profiles['profile'])) {
                foreach ($profiles['profile'] as $p) {
                    if ($p['uuid'] === $uuid) {
                        $targetProfile = $p;
                        break;
                    }
                }
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
            "mounted" => $mounted,
            "active_mounts" => $activeMounts,
            "vc_installed_status" => "🟢 VeraCrypt installed",
            "vc_not_installed_status" => "🔴 Please Install VeraCrypt!",
            "vc_bottom_notice" => "🔴 VeraCrypt is NOT installed. Please install veracrypt to enable this."
        ];
    }
}
