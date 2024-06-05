<?php

namespace idekite\flexcodesdk;

use App\DemoFinger;
use Config;

class flexcodesdk
{
    public static function getDevice()
    {
        $data['device_name']        =  env('FLEXCODE_DEVICE');
        $data['serial_number']      =  env('FLEXCODE_SN');
        $data['verification_code']  =  env('FLEXCODE_VC');
        $data['activation_code']    =  env('FLEXCODE_AC');
        $data['verification_key']   =  env('FLEXCODE_VKEY');

        return response()->json($data);
    }

    public function registerUrl($user_id)
    {
        return  $user_id . ';SecurityKey;15;'.url('fingerprints/register/' . $user_id).';' . url('fingerprints/ac');
    }

    public function getDeviceBySn($sn)
    {
        $devices = Config::get('flexcodesdk', 'devices');
        foreach ($devices as $device) {
            if($device['sn'] === $sn){
                return $device;
            }
        }
        return false;
    }

    public function decodeRegistrationData($serialized_data)
    {   
        @list($vStamp, $sn, $user_id, $regTemp) = explode(";", $serialized_data);
        if( !isset($vStamp) || !isset($sn) || !isset($user_id) || !isset($regTemp)){
            return array();
        }
        
        return array(
            'vStamp'     =>  $vStamp,
            'sn'         =>  $sn,
            'user_id'    =>  $user_id,
            'regTemp'    =>  $regTemp,
        );
        
    }

    public function isValidRegistration($user, $data)
    {
        
        if(!empty($user->finger_data) || $user->user_id !== $data['user_id']){
            return false;
        }
        
        $device = flexcodesdk::getDeviceBySn($data['sn']);
        
        $salt = md5($device['ac'].$device['vkey'].$data['regTemp'].$data['sn'].$data['user_id']);
        return (strtoupper($data['vStamp']) == strtoupper($salt)) ? true : false;
    }

    public function register($id, $serialized_data)
    {
        $user = \App\DemoUsers::where('case_id', $id)->first();

        if ($user == NULL) {
            $result['message'] = 'User not found';
            return $result;
        }else{
            $data = explode(";", $serialized_data);

            if(empty($data[3])) {
                $result['message'] = 'Error decoding fingerprint data';
                return $result;
            }else{
                $fingerprint = DemoFinger::where('user_id', $id)->first();
                if($fingerprint){
                    $fingerprint->delete();
                }
                $save_fingerprint = new \App\DemoFinger;
                $save_fingerprint->user_id = $id;
                $save_fingerprint->finger_id = '1';
                $save_fingerprint->finger_data = $data[3];
                $save_fingerprint->save();

                $result['message'] = 'Fingerprints successfully registered';
                return $result;
            }
        }

        
    }

    public function verificationUrl($user, $extra = array())
    {
        $query_string = http_build_query($extra);
        return $user->user_id . ";". $user->finger_data.";SecurityKey;". '15' .";". url('fingerprints/verify/' . $user->user_id . '?' . $query_string) .";". url('fingerprints/ac');
    }

    public function verify($id, $serialized_data)
    {
        $verified = false;
        $message = '';
        try{
            $user = \App\DemoFinger::where('case_id', $id)->firstOrFail();
        }
        catch(Exception $e){
            $message = 'User not found';
            $result = array(
                'verified' => $verified,
                'user' => null,
                'message' => $message,
            );
            return $result;
        }
        @list($user_id, $vStamp, $time, $sn) = explode(";", $serialized_data);
        if( !isset($user_id) || !isset($vStamp) || !isset($time) || !isset($sn)){
            $message = 'Incorrect fingerprint data';
            $result = array(
                'verified' => $verified,
                'user' => $user,
                'message' => $message,
            );
            return $result;
        }
        
        if($user->user_id != $user_id){
            $message =  'User mismatch';
            $result = array(
                'verified' => $verified,
                'user' => $user,
                'message' => $message,
            );
            return $result;
        }
        if(empty($user->finger_data)){
            $message =  'Fingerprints unregistered';
            $result = array(
                'verified' => $verified,
                'user' => $user,
                'message' => $message,
            );
            return $result;
        }
        
        $fingerData = $user->finger_data;
        $device     = flexcodesdk::getDeviceBySn($sn);
            
        $salt = md5($sn.$fingerData.$device['vc'].$time.$user_id.$device['vkey']);
        
        if(strtoupper($vStamp) == strtoupper($salt)){
            $result = array(
                'verified' => true,
                'user' => $user,
                'message' => 'Verication success',
            );
            return $result;
        }
        $result = array(
            'user' => $user,
            'message' => 'Fingerprint mismatch',
        );
        return $result;
    }

    public function getRegistrationLink($id)
    {
        return 'finspot:FingerspotReg;' . base64_encode(url('fingerprints/register/' . $id));
    }

}