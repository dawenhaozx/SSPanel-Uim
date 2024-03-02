<?php

declare(strict_types=1);

namespace App\Services\Subscribe;

use App\Models\Config;
use App\Services\Subscribe;
use function base64_encode;
use function json_decode;
use function json_encode;
use const PHP_EOL;

final class V2Ray extends Base
{
    public function getContent($user): string
    {
        $links = '';
        //判断是否开启V2Ray订阅
        if (! Config::obtain('enable_v2_sub')) {
            return $links;
        }

        $nodes_raw = Subscribe::getUserNodes($user);

        foreach ($nodes_raw as $node_raw) {
            $node_custom_config = json_decode($node_raw->custom_config, true);

            //跳过非v2ray型节点
            if (! (int) $node_raw->sort === 11) {
                continue;
            }
            //检查是否vless
            $enable_vless = array_key_exists('enable_vless', $node_custom_config) ? $node_custom_config['enable_vless'] : '0';
            if ((int) $enable_vless === 1) {
                $config = [
                    //vless基本字段
                    "name" => self::encodeURIComponent($node_raw->name),
                    "add" => $server,
                    "port" => $node_custom_config['v2_port'] ?? ($node_custom_config['offset_port_user'] ?? ($node_custom_config['offset_port_node'] ?? 443)),
                    "type" => $node_custom_config['network'] ?? 'tcp',
                    "encryption" => 'none',
                    //network区分字段
                    "host" => $node_custom_config['host'] ?? '',
                    "path" => self::encodeURIComponent($node_custom_config['path'] ?? '/'),
                    "headerType" => 'none',
                    "quicSecurity" => $node_custom_config['quicSecurity'] ?? 'none',
                    "serviceName" => self::encodeURIComponent($node_custom_config['serviceName'] ?? ($node_custom_config['servicename'] ?? '')),
                    "mode" => 'gun',
                    //tls、xtls、reality支持
                    "security" => $node_custom_config['security'] ?? 'none',
                    "flow" => $node_custom_config['flow'] ?? 'none',
                    "sni" => $node_custom_config['host'] ?? '',
                    "pbk" => $node_custom_config['publicKey'] ?? '',
                    "sid" => $node_custom_config['shortId'] ?? '',
                ];
                $output = "vless://" . $user->uuid . "@" . $config['add'] . ":" . $config['port'];
                $output .= "?type={$config['type']}&encryption={$config['encryption']}&security={$config['security']}";

                if ($config['security'] !== 'none') {
                    $output .= "&sni={$config['sni']}";
                    if ($config['flow'] !== 'none') {
                        $output .= "&flow={$config['flow']}";
                    }
                    if ((string) $config['security'] === 'reality') {
                        $output .= "&pbk={$config['pbk']}&sid={$config['sid']}";
                    }
                }

                switch ($config['type']) {
                    case 'tcp':
                        $header = $node_custom_config['header'] ?? ['type' => 'none'];
                        $config['headerType'] = $header['type'] ?? '';
                        $output .= "&headerType={$config['headerType']}";
                        break;

                    case 'kcp':
                        $header = $node_custom_config['header'] ?? ['type' => 'none'];
                        $config['headerType'] = $header['type'] ?? '';
                        $output .= "&headerType={$config['headerType']}&seed={$config['path']}";
                        break;

                    case 'ws':
                        $output .= "&path={$config['path']}&host={$config['host']}";
                        break;

                    case 'h2':
                        $output .= "&path={$config['path']}&host={$config['host']}";
                        break;

                    case 'quic':
                        $header = $node_custom_config['header'] ?? ['type' => 'none'];
                        $config['headerType'] = $header['type'] ?? '';
                        $output .= "&quicSecurity={$config['quicSecurity']}&headerType={$config['headerType']}";
                        if ((string) $config['quicSecurity'] !== 'none') {
                            $output .= "&key={$config['path']}";
                        }
                        break;

                    case 'grpc':
                        if (isset($node_custom_config['multiMode'])) {
                            $config['mode'] = $node_custom_config['multiMode'] ? "multi" : "gun";
                        }
                        $output .= "&serviceName={$config['serviceName']}&mode={$config['mode']}";
                        break;
                }

                $output .= "&fp=chrome#" . $config['name'];
                $links .= $output . "\r\n";
            } else {
                $v2_port = $node_custom_config['offset_port_user'] ?? ($node_custom_config['offset_port_node'] ?? 443);
                $security = $node_custom_config['security'] ?? 'none';
                $network = $node_custom_config['network'] ?? '';
                $header = $node_custom_config['header'] ?? ['type' => 'none'];
                $header_type = $header['type'] ?? '';
                $host = $node_custom_config['header']['request']['headers']['Host'][0] ?? $node_custom_config['host'] ?? '';
                $path = $node_custom_config['header']['request']['path'][0] ?? $node_custom_config['path'] ?? '/';

                $v2rayn_array = [
                    'v' => '2',
                    'ps' => $node_raw->name,
                    'add' => $node_raw->server,
                    'port' => $v2_port,
                    'id' => $user->uuid,
                    'aid' => 0,
                    'net' => $network,
                    'type' => $header_type,
                    'host' => $host,
                    'path' => $path,
                    'tls' => $security,
                ];

                $links .= 'vmess://' . base64_encode(json_encode($v2rayn_array)) . PHP_EOL;
            }
        }

        return $links;
    }

    public static function encodeURIComponent($str)
    {
        $revert = [
            '%21' => '!',
            '%2A' => '*',
            '%27' => "'",
            '%28' => '(',
            '%29' => ')',
        ];
        return strtr(rawurlencode($str), $revert);
    }
}
