<?php

/**
 * @Author: Feri Harjulianto
 * @Date:   2018-09-05 14:14:41
 * @Last Modified by:   Feri Harjulianto
 * @Last Modified time: 2018-09-05 14:15:03
 */

namespace App;

use Illuminate\Database\Eloquent\Model;

class DemoUsers extends Model
{
    protected $table = 'demo_users';

    protected $guarded = [
    	'_token',
    	'updated_at',
    	'created_at'
    ];
    public $timestamps = true;
    protected $primaryKey = 'id';
}
