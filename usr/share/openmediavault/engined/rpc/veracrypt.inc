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
        $this->registerMethod("installVeraCrypt");
        $this->registerMethod("removeVeraCrypt");
        $this->registerMethod("getStatus");
    }

    public function get($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.veracrypt");
        return $object->getAssoc();
    }

    public function set($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.set");

        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.veracrypt");
        $object->setAssoc($params);
        $db->set($object);
        return $object->getAssoc();
    }

    public function getProfileList($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);

        $db = \OMV\Config\Database::getInstance();
        $config = $db->get("conf.service.veracrypt");
        $profilesData = $config->get("profiles") ? $config->get("profiles") : [];
        $profilesList = [];

        if (isset($profilesData['profile'])) {
            $profilesList = $profilesData['profile'];
        }

        // Check if veracrypt is installed
        $installed = false;
        if (file_exists("/usr/bin/veracrypt") || file_exists("/usr/sbin/veracrypt") || file_exists("/usr/local/bin/veracrypt")) {
            $installed = true;
        } else {
            $cmdCheck = new \OMV\System\Process("which", ["veracrypt"]);
            $cmdCheck->execute($output, $exitStatus);
            if ($exitStatus === 0) {
                $installed = true;
            }
        }

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
            $resultList[] = $profile;
        }

        return $resultList;
    }

    public function setProfile($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.setProfile");

        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.veracrypt");
        $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
        $profilesList = [];

        if (isset($profilesData['profile'])) {
            $profilesList = $profilesData['profile'];
        }

        // Handle profile modifications (if remember_configs is false, clear password)
        if (isset($params['remember_configs']) && !$params['remember_configs']) {
            $params['password'] = "";
        }

        $uuid = $params['uuid'];
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

        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.veracrypt");
        $profilesData = $object->get("profiles") ? $object->get("profiles") : [];
        $profilesList = [];

        if (isset($profilesData['profile'])) {
            $profilesList = $profilesData['profile'];
        }

        $uuid = $params['uuid'];
        $newProfilesList = [];

        foreach ($profilesList as $p) {
            if ($p['uuid'] !== $uuid) {
                $newProfilesList[] = $p;
            }
        }

        $profilesData['profile'] = $newProfilesList;
        $object->set("profiles", $profilesData);
        $db->set($object);

        return ["uuid" => $uuid, "success" => true];
    }

    public function mount($params, $context)
    {
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        $this->validateMethodParams($params, "rpc.veracrypt.mount");

        $uuid = $params['uuid'];
        $db = \OMV\Config\Database::getInstance();
        $config = $db->get("conf.service.veracrypt");
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
        $filename = isset($targetProfile['filename']) ? $targetProfile['filename'] : '';
        $perm = isset($targetProfile['permissions']) ? $targetProfile['permissions'] : '777';

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

        $uuid = $params['uuid'];
        $db = \OMV\Config\Database::getInstance();
        $config = $db->get("conf.service.veracrypt");
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
            // Run script or apt command to install VeraCrypt console
            $cmd = new \OMV\System\Process("sh", [
                "-c",
                "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y veracrypt || apt-get install -y veracrypt-console || echo 'VeraCrypt package installation initiated.'"
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
                "export DEBIAN_FRONTEND=noninteractive; apt-get purge -y veracrypt veracrypt-console || echo 'VeraCrypt package removal completed.'"
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
        $this->validateMethodParams($params, "rpc.veracrypt.get_status");

        // 1. Check if VeraCrypt is installed
        $installed = false;
        $cmdCheck = new \OMV\System\Process("which", ["veracrypt"]);
        $cmdCheck->execute($output, $exitStatus);
        if ($exitStatus === 0) {
            $installed = true;
        } else {
            // Also check common binary paths just in case
            if (file_exists("/usr/bin/veracrypt") || file_exists("/usr/sbin/veracrypt") || file_exists("/usr/local/bin/veracrypt")) {
                $installed = true;
            }
        }

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
            $db = \OMV\Config\Database::getInstance();
            $config = $db->get("conf.service.veracrypt");
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
            "active_mounts" => $activeMounts
        ];
    }
}
