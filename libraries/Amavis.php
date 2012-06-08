<?php

/**
 * Amavis class.
 *
 * @category   Apps
 * @package    Mail_Filter
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2006-2012 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/mail_filter/
 */

///////////////////////////////////////////////////////////////////////////////
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// N A M E S P A C E
///////////////////////////////////////////////////////////////////////////////

namespace clearos\apps\mail_filter;

///////////////////////////////////////////////////////////////////////////////
// B O O T S T R A P
///////////////////////////////////////////////////////////////////////////////

$bootstrap = getenv('CLEAROS_BOOTSTRAP') ? getenv('CLEAROS_BOOTSTRAP') : '/usr/clearos/framework/shared';
require_once $bootstrap . '/bootstrap.php';

///////////////////////////////////////////////////////////////////////////////
// T R A N S L A T I O N S
///////////////////////////////////////////////////////////////////////////////

clearos_load_language('mail_filter');

///////////////////////////////////////////////////////////////////////////////
// D E P E N D E N C I E S
///////////////////////////////////////////////////////////////////////////////

// Classes
//--------

use \clearos\apps\base\Daemon as Daemon;
use \clearos\apps\base\File as File;
use \clearos\apps\base\File_Types as File_Types;
use \clearos\apps\mail_filter\Amavis as Amavis;
use \clearos\apps\smtp\Postfix as Postfix;

clearos_load_library('base/Daemon');
clearos_load_library('base/File');
clearos_load_library('base/File_Types');
clearos_load_library('mail_filter/Amavis');
clearos_load_library('smtp/Postfix');

// Exceptions
//-----------

use \clearos\apps\base\Engine_Exception as Engine_Exception;
use \clearos\apps\base\Validation_Exception as Validation_Exception;

clearos_load_library('base/Engine_Exception');
clearos_load_library('base/Validation_Exception');

///////////////////////////////////////////////////////////////////////////////
// C L A S S
///////////////////////////////////////////////////////////////////////////////

/**
 * Amavis class.
 *
 * @category   Apps
 * @package    Mail_Filter
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2006-2012 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/mail_filter/
 */

class Amavis extends Daemon
{
    ///////////////////////////////////////////////////////////////////////////////
    // C O N S T A N T S
    ///////////////////////////////////////////////////////////////////////////////

    const FILE_CONFIG = '/etc/amavisd/api.conf';
    const DEFAULT_FINAL_SPAM_DESTINY = 'D_BOUNCE';
    const DEFAULT_FINAL_VIRUS_DESTINY = 'D_DISCARD';
    const DEFAULT_KILL_LEVEL = 25;
    const DEFAULT_MAX_CHILDREN = 2;
    const DEFAULT_QUARANTINE_LEVEL = 'undef';
    const DEFAULT_SUBJECT_TAG_LEVEL = 2;
    const TYPE_PASS = 'D_PASS';
    const TYPE_BOUNCE = 'D_BOUNCE';
    const TYPE_DISCARD = 'D_DISCARD';
    const POLICY_PASS = 'pass';
    const POLICY_BOUNCE = 'bounce';
    const POLICY_DISCARD = 'discard';
    const POLICY_QUARANTINE = 'quarantine';
    const QUARANTINE_METHOD_SQL = 'sql:';
    const CONSTANT_UNDEF = 'undef';
    const CONSTANT_REMOVE_PARAMETER = 'pcn_remove';
    const CONSTANT_MIME_TYPES = 'MIME types';
    const CONSTANT_BANNED_EXTENSIONS = 'Banned extensions';
    const CONSTANT_DOUBLE_EXTENSIONS = 'Double extensions';

    ///////////////////////////////////////////////////////////////////////////////
    // V A R I A B L E S
    ///////////////////////////////////////////////////////////////////////////////

    protected $params = array();
    protected $banned_extensions = array();
    protected $double_extensions = array();
    protected $mime_types = array();
    protected $is_loaded = FALSE;

    ///////////////////////////////////////////////////////////////////////////////
    // M E T H O D S
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * Amavis constructor.
     */

    public function __construct()
    {
        clearos_profile(__METHOD__, __LINE__);

        parent::__construct('amavisd');
    }

    /**
     * Returns the state of the antispam engine.
     *
     * @return boolean state
     * @throws Engine_Exception
     */

    public function get_antispam_state()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        if (isset($this->params['bypass_spam_checks_maps'])) {
            if ($this->params['bypass_spam_checks_maps'] == "(1)")
                return FALSE;
            else
                throw new Engine_Exception('Custom configuration detected');
        } else {
            return TRUE;
        }
    }

    /**
     * Returns antispam discard and quarantine settings.
     *
     * The discard/quarantine logic in the Amavis configuration file is a bit
     * non-intuitive.  For example, the sa_kill_level_deflt can be either the
     * spam level used to discard a message, or, the spam level used to quarantine
     * the message; it depends on how other parameters are set!  To hide these 
     * details in the API, coarse methods are created:
     *
     * Get/SetAntispamDiscardAndQuarantine($discard, $discard_threshold, $quarantine, $quarantine_threshold)
     *
     * The logic behind these methods is shown in the following table:
     *
     *                            | final_x_destiny | sa_kill_level_deflt | x_quarantine_method | sa_quarantine_cutoff_level
     *                            +-----------------+---------------------+---------------------+---------------------------
     * Discard + Quarantine       |    D_DISCARD    | used for quarantine |        sql:         |     used for discard
     * Discard + No Quarantine    |    D_DISCARD    |   used for discard  |      <blank>        |         undef (n/a)
     * No Discard + Quarantine    |    D_DISCARD    | used for quarantine |        sql:         |         undef
     * No Discard + No Quarantine |      D_PASS     |         n/a         |      <blank>        |         undef (n/a)
     *
     * @return string block type
     * @throws Engine_Exception
     */

    public function get_antispam_discard_and_quarantine()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        // Get the raw configuration data
        //-------------------------------

        if (isset($this->params['final_spam_destiny']))
            $final_spam_destiny = $this->params['final_spam_destiny'];
        else
            $final_spam_destiny = Amavis::DEFAULT_FINAL_SPAM_DESTINY;

        if (isset($this->params['sa_kill_level_deflt']))
            $sa_kill_level = $this->params['sa_kill_level_deflt'];
        else
            $sa_kill_level = Amavis::DEFAULT_KILL_LEVEL;

        if (isset($this->params['spam_quarantine_method']))
            $spam_quarantine_method = $this->params['spam_quarantine_method'];
        else
            $spam_quarantine_method = '';

        if (isset($this->params['sa_quarantine_cutoff_level'])) 
            $sa_quarantine_level = $this->params['sa_quarantine_cutoff_level'];
        else
            $sa_quarantine_level = Amavis::DEFAULT_QUARANTINE_LEVEL;

        // Apply the logic described above
        //--------------------------------

        $info = array();

        if (($final_spam_destiny == Amavis::TYPE_DISCARD) 
            && ($spam_quarantine_method != '') && ($sa_quarantine_level != Amavis::CONSTANT_UNDEF)) {
            $info['discard'] = TRUE;
            $info['quarantine'] = TRUE;
            $info['discard_level'] = $sa_quarantine_level;
            $info['quarantine_level'] = $sa_kill_level;
        } else if (($final_spam_destiny == Amavis::TYPE_DISCARD) && ($spam_quarantine_method == '')) {
            $info['discard'] = TRUE;
            $info['quarantine'] = FALSE;
            $info['discard_level'] = $sa_kill_level;
            $info['quarantine_level'] = $sa_kill_level - 5;
        } else if (($final_spam_destiny == Amavis::TYPE_DISCARD)
            && ($spam_quarantine_method != '') && ($sa_quarantine_level == Amavis::CONSTANT_UNDEF)) {
            $info['discard'] = FALSE;
            $info['quarantine'] = TRUE;
            $info['discard_level'] = $sa_kill_level + 5;
            $info['quarantine_level'] = $sa_kill_level;
        } else if (($final_spam_destiny == Amavis::TYPE_PASS)) {
            $info['discard'] = FALSE;
            $info['quarantine'] = FALSE;
            $info['discard_level'] = 20;
            $info['quarantine_level'] = 15;
        }

        return $info;
    }

    /**
     * Returns antivirus policy.
     *
     * Return values:
     * - Amavis::POLICY_PASS
     * - Amavis::POLICY_DISCARD
     * - Amavis::POLICY_QUARANTINE
     *
     * @return string antivirus policy
     * @throws Engine_Exception
     */

    public function get_antivirus_policy()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        $final_virus_destiny = $this->params['final_virus_destiny'];
        $virus_quarantine_method = $this->params['virus_quarantine_method'];

        if ($final_virus_destiny == Amavis::TYPE_PASS) {
            $policy = Amavis::POLICY_PASS;
        } else if (($final_virus_destiny == Amavis::TYPE_DISCARD) && ($virus_quarantine_method == '')) {
            $policy = Amavis::POLICY_DISCARD;
        } else if (($final_virus_destiny == Amavis::TYPE_DISCARD) && ($virus_quarantine_method != '')) {
            $policy = Amavis::POLICY_QUARANTINE;
        }

        return $policy;
    }

    /**
     * Returns the state of the antivirus engine.
     *
     * @return boolean state
     * @throws Engine_Exception
     */

    public function get_antivirus_state()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        if (isset($this->params['bypass_virus_checks_maps'])) {
            if ($this->params['bypass_virus_checks_maps'] == "(1)")
                return FALSE;
            else
                throw new Engine_Exception('Custom configuration detected');
        } else {
            return TRUE;
        }
    }

    /**
     * Returns bad header policy.
     *
     * @return string bad header policy type
     * @throws Engine_Exception
     */

    public function get_bad_header_policy()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        $final_bad_header_destiny = $this->params['final_bad_header_destiny'];
        $bad_header_quarantine_method = $this->params['bad_header_quarantine_method'];

        if ($final_bad_header_destiny == Amavis::TYPE_PASS) {
            $policy = Amavis::POLICY_PASS;
        } else if ($final_bad_header_destiny == Amavis::TYPE_BOUNCE) {
            $policy = Amavis::POLICY_BOUNCE;
        } else if (($final_bad_header_destiny == Amavis::TYPE_DISCARD) && ($bad_header_quarantine_method == '')) {
            $policy = Amavis::POLICY_DISCARD;
        } else if (($final_bad_header_destiny == Amavis::TYPE_DISCARD) && ($bad_header_quarantine_method != '')) {
            $policy = Amavis::POLICY_QUARANTINE;
        }

        return $policy;
    }

    /**
     * Returns banned files policy.
     *
     * @return string banned files policy
     * @throws Engine_Exception
     */

    public function get_banned_policy()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        $final_banned_destiny = $this->params['final_banned_destiny'];
        $banned_files_quarantine_method = $this->params['banned_files_quarantine_method'];

        if ($final_banned_destiny == Amavis::TYPE_PASS) {
            $policy = Amavis::POLICY_PASS;
        } else if ($final_banned_destiny == Amavis::TYPE_BOUNCE) {
            $policy = Amavis::POLICY_BOUNCE;
        } else if (($final_banned_destiny == Amavis::TYPE_DISCARD) && ($banned_files_quarantine_method == '')) {
            $policy = Amavis::POLICY_DISCARD;
        } else if (($final_banned_destiny == Amavis::TYPE_DISCARD) && ($banned_files_quarantine_method != '')) {
            $policy = Amavis::POLICY_QUARANTINE;
        }

        return $policy;
    }

    /**
     * Returns list of available extensions.
     *
     * @return array list of available extensions
     * @throws Engine_Exception
     */

    public function get_banned_extension_list()
    {
        clearos_profile(__METHOD__, __LINE__);

        $file_types = new File_Types();

        return $file_types->get_file_extensions();
    }

    /**
     * Returns list of banned extensions.
     *
     * @return array list of banned extensions
     * @throws Engine_Exception
     */

    public function get_banned_extensions()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        return $this->banned_extensions;
    }

    /**
     * Returns the maximum number of children.
     *
     * @return integer maximum number of children.
     * @throws Engine_Exception
     */

    public function get_max_children()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        if (isset($this->params['max_servers']))
            return $this->params['max_servers'];
        else
            return self::DEFAULT_MAX_CHILDREN;
    }

    /**
     * Returns the subject tag for spam.
     *
     * @return string subject tag
     * @throws Engine_Exception
     */

    public function get_subject_tag()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        if (isset($this->params['sa_spam_subject_tag']))
            return $this->params['sa_spam_subject_tag'];
        else
            return '';
    }

    /**
     * Returns required score to use subject tag.
     *
     * @return float required hits
     * @throws Engine_Exception
     */

    public function get_subject_tag_level()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        if (isset($this->params['sa_tag2_level_deflt']))
            return $this->params['sa_tag2_level_deflt'];
        else
            return self::DEFAULT_SUBJECT_TAG_LEVEL;
    }

    /**
     * Returns state of subject tag re-writing.
     *
     * @return boolean TRUE if subject tag rewriting is on
     * @throws Engine_Exception
     */

    public function get_subject_tag_state()
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_loaded)
            $this->_load_config();

        if (isset($this->params['sa_spam_modifies_subj']) && ($this->params['sa_spam_modifies_subj'] == 1))
            return TRUE;
        else
            return FALSE;
    }

    /**
     * Returns a list policy options.
     *
     * @return array
     */

    function get_policy_options($policy = '')
    {
        clearos_profile(__METHOD__, __LINE__);
            
        $options = Array(
            self::POLICY_PASS => lang('mail_filter_pass_through'),
            self::POLICY_DISCARD => lang('mail_filter_discard'),
        );

        // FIXME: add quarantine
        // self::POLICY_QUARANTINE => lang('mail_filter_quarantine')

        if (preg_match('/banned_extension/', $policy))
	        $options[self::POLICY_BOUNCE] = lang('mail_filter_bounce');

        return $options;
    }

    /**
     * Returns antispam discard and quarantine settings.
     *
     * @param boolean $discard          state of discard engine
     * @param integer $discard_level    discard level
     * @param boolean $quarantine       state of quarantine engine
     * @param integer $quarantine_level quarantine level
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_antispam_discard_and_quarantine($discard, $discard_level, $quarantine, $quarantine_level)
    {
        clearos_profile(__METHOD__, __LINE__);

        if ($discard && ($discard_level > 0) && $quarantine && ($quarantine_level > 0)) {
            $this->_set_parameter('$final_spam_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$sa_kill_level_deflt', $quarantine_level);
            $this->_set_parameter('$spam_quarantine_method', "'" . Amavis::QUARANTINE_METHOD_SQL . "'");
            $this->_set_parameter('$sa_quarantine_cutoff_level', $discard_level);
        } else if ($discard && ($discard_level > 0) && !$quarantine) {
            $this->_set_parameter('$final_spam_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$sa_kill_level_deflt', $discard_level);
            $this->_set_parameter('$spam_quarantine_method', '');
            $this->_set_parameter('$sa_quarantine_cutoff_level', Amavis::CONSTANT_UNDEF);
        } else if (!$discard && $quarantine && ($quarantine_level > 0)) {
            $this->_set_parameter('$final_spam_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$sa_kill_level_deflt', $quarantine_level);
            $this->_set_parameter('$spam_quarantine_method', "'" . Amavis::QUARANTINE_METHOD_SQL . "'");
            $this->_set_parameter('$sa_quarantine_cutoff_level', Amavis::CONSTANT_UNDEF);
        } else if (!$discard && !$quarantine) {
            $this->_set_parameter('$final_spam_destiny', Amavis::TYPE_PASS);
            $this->_set_parameter('$spam_quarantine_method', '');
            $this->_set_parameter('$sa_quarantine_cutoff_level', Amavis::CONSTANT_UNDEF);
        }
    }

    /**
     * Sets the state of the antispam engine.
     *
     * @param boolean $state state of the antispam engine
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_antispam_state($state)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! is_bool($state))
            throw new Validation_Exception(lang('base_parameter_id_invalid'));

        if ($state)
            $this->_set_parameter('@bypass_spam_checks_maps', self::CONSTANT_REMOVE_PARAMETER);
        else
            $this->_set_parameter('@bypass_spam_checks_maps', "(1)");
    }

    /**
     * Sets the antivirus policy.
     *
     * @param string $policy antivirus policy
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_antivirus_policy($policy)
    {
        clearos_profile(__METHOD__, __LINE__);

        if ($policy == Amavis::POLICY_PASS) {
            $this->_set_parameter('$final_virus_destiny', Amavis::TYPE_PASS);
            $this->_set_parameter('$virus_quarantine_method', '');
        } else if ($policy == Amavis::POLICY_DISCARD) {
            $this->_set_parameter('$final_virus_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$virus_quarantine_method', '');
        } else if ($policy == Amavis::POLICY_QUARANTINE) {
            $this->_set_parameter('$final_virus_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$virus_quarantine_method', "'" . Amavis::QUARANTINE_METHOD_SQL . "'");
        } else {
            throw new Validation_Exception(lang('mail_filter_virus_detected_policy') . ' - ' . lang('base_invalid'));
        }
    }

    /**
     * Sets the state of the antivirus engine.
     *
     * @param boolean $state state of the antivirus engine
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_antivirus_state($state)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! is_bool($state))
            throw new Validation_Exception(lang('base_parameter_is_invalid'));

        if ($state)
            $this->_set_parameter('@bypass_virus_checks_maps', self::CONSTANT_REMOVE_PARAMETER);
        else
            $this->_set_parameter('@bypass_virus_checks_maps', "(1)");
    }

    /**
     * Sets the bad header policy.
     *
     * @param string $policy bad header policy
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_bad_header_policy($policy)
    {
        clearos_profile(__METHOD__, __LINE__);

        if ($policy == Amavis::POLICY_PASS) {
            $this->_set_parameter('$final_bad_header_destiny', Amavis::TYPE_PASS);
            $this->_set_parameter('$bad_header_quarantine_method', '');
        } else if ($policy == Amavis::POLICY_DISCARD) {
            $this->_set_parameter('$final_bad_header_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$bad_header_quarantine_method', '');
        } else if ($policy == Amavis::POLICY_QUARANTINE) {
            $this->_set_parameter('$final_bad_header_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$bad_header_quarantine_method', "'" . Amavis::QUARANTINE_METHOD_SQL . "'");
        } else {
            throw new Validation_Exception(lang('mail_filter_bad_header_policy') . ' - ' . lang('base_invalid'));
        }
    }

    /**
     * Sets the banned files policy.
     *
     * @param string $policy banned files policy
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_banned_policy($policy)
    {
        clearos_profile(__METHOD__, __LINE__);

        if ($policy == Amavis::POLICY_PASS) {
            $this->_set_parameter('$final_banned_destiny', Amavis::TYPE_PASS);
            $this->_set_parameter('$banned_files_quarantine_method', '');
        } else if ($policy == Amavis::POLICY_BOUNCE) {
            $this->_set_parameter('$final_banned_destiny', Amavis::TYPE_BOUNCE);
            $this->_set_parameter('$banned_files_quarantine_method', '');
        } else if ($policy == Amavis::POLICY_DISCARD) {
            $this->_set_parameter('$final_banned_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$banned_files_quarantine_method', '');
        } else if ($policy == Amavis::POLICY_QUARANTINE) {
            $this->_set_parameter('$final_banned_destiny', Amavis::TYPE_DISCARD);
            $this->_set_parameter('$banned_files_quarantine_method', "'" . Amavis::QUARANTINE_METHOD_SQL . "'");
        } else {
            throw new Validation_Exception(lang('mail_filter_banned_file_extension_policy') . ' - ' . lang('base_invalid'));
        }
    }

    /**
     * Sets list of banned extensions.
     *
     * @param array $extensions list of banned extensions
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_banned_extensions($extensions)
    {
        clearos_profile(__METHOD__, __LINE__);

        $badlist = array();
        $allowedextensions = array_keys($this->get_banned_extension_list());

        foreach ($extensions as $extension) {
            if (!in_array($extension, $allowedextensions))
                array_push($badlist, $extension);
        }

        if (count($badlist) > 0) {
            $badout = implode(' ', $badlist);
            throw new Validation_Exception(lang('base_file_extension') . " ($badout) - " . lang('base_invalid'));
        }

        $this->is_loaded = FALSE;

        $amavislist = implode('|', $extensions);

        $newlines = array();

        $file = new File(self::FILE_CONFIG);
        $lines = $file->get_contents_as_array();

        $skip = FALSE;
        
        foreach ($lines as $line) {
            if ($skip) {
                $skip = FALSE;
            } else {
                if (preg_match("/^\s*# " . self::CONSTANT_BANNED_EXTENSIONS . "/", $line)) {
                    $newlines[] = '  # ' . self::CONSTANT_BANNED_EXTENSIONS;
                    $newlines[] = '  qr\'\.(' . $amavislist . ')$\'i,';
                    $skip = TRUE;
                } else {
                    $newlines[] = $line;
                }
            }
        }

        $file->dump_contents_from_array($newlines);
    }

    /**
     * Sets the maximum number of children.
     *
     * @param integer $children maximum number of children to spawn.
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_max_children($children)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! $this->is_valid_max_children($children))
            throw new Validation_Exception(lang('mail_filter_mail_volume') . " - " . lang('base_invalid'));

        $this->_set_parameter('$max_servers', $children);
    }

    /**
     * Sets the subject tag.
     *
     * @param string $tag subject tag
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_subject_tag($tag)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_subject_tag($tag));

        $this->_set_parameter('$sa_spam_subject_tag', "\"$tag\"");
    }

    /**
     * Sets subject tag level.
     *
     * @param float $level subbject tag level
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_subject_tag_level($level)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_subject_tag_level($level));

        $this->_set_parameter('$sa_tag2_level_deflt', $level);
    }

    /**
     * Sets if the subject should be rewritten
     *
     * @param boolean $rewrite TRUE if the subject should be rewritten
     *
     * @return void
     */

    public function set_subject_tag_state($rewrite)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_subject_tag_state($rewrite));

        if ($rewrite)
            $value = 1;
        else
            $value = 0;

        $this->_set_parameter('$sa_spam_modifies_subj', $value);
    }

    /**
     * Synchronizes domain information from Postfix configuration.
     *
     * @return void
     */

    public function synchronize_domains()
    {
        clearos_profile(__METHOD__, __LINE__);

        $postfix = new Postfix();

        // Local domain maps
        //------------------

        $local_domains = $postfix->get_local_domains();

        $local_domains_maps = "";

        foreach ($local_domains as $domain) 
            $local_domains_maps .= " \".$domain\",";

        $local_domains_maps = ltrim($local_domains_maps);
        $local_domains_maps = rtrim($local_domains_maps, ",");
echo "( [ $local_domains_maps ] )\n";

        $file = new File(self::FILE_CONFIG);
        $file->replace_lines('/^@local_domains_maps\s*=\s*/', "@local_domains_maps = ( [ $local_domains_maps ] );\n");

        // Primary domain
        //---------------

        $primary_domain = $postfix->get_domain();
        $primary_domain =  "\$mydomain = \"$primary_domain\";\n";

        $file = new File(self::FILE_CONFIG);
        $match = $file->replace_lines('/^\$mydomain\s*=\s*/', $primary_domain);

        if ($match === 0)
            $file->add_lines_before($primary_domain, '/^@local_domains_maps\s*=/');
    }

    ///////////////////////////////////////////////////////////////////////////////
    // V A L I D A T I O N  M E T H O D S
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * Validation routine for block level.
     *
     * @param string $level block level
     *
     * @return string error message if block level is invalid
     */
    
    public function validate_block_level($level)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (preg_match('/^[0-9]+$/', $level))
            return;

        if (preg_match('/^[0-9]+\.[0-9]{1,2}$/', $level))
            return;

        return lang('mail_filter_block_level_invalid');
    }

    /**
     * Validation routine for discard policy level.
     *
     * @param string $level discard policy level
     *
     * @return string error message if discard policy level is invalid
     */
    
    public function validate_discard_policy_level($level)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (preg_match("/^[0-9]+$/", $level))
            return;

        if (preg_match("/^[0-9]+\.[0-9]{1,2}$/", $level))
            return;

        return lang('mail_filter_discard_policy_level_invalid');
    }

    /**
     * Validation routine for discard policy tag state.
     *
     * @param string $state discard policy tag state
     *
     * @return string error message if discard policy tag state is invalid
     */
    
    public function validate_discard_policy_state($state)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (!clearos_is_valid_boolean($state))
            return lang('mail_filter_discard_policy_state_invalid');
    }

    /**
     * Validation routine for max children.
     *
     * @param string $children max children
     *
     * @return string error message if max children is invalid
     */
    
    public function validate_max_children($children)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (!(preg_match("/^\d+$/", $children) && ($children > 0) && ($children <= 100)))
            return lang('mail_filter_max_children_invalid');
    }

    /**
     * Validation routine for subject tag.
     *
     * @param string $tag subject tag
     *
     * @return string error message if subject tag is invalid
     */
    
    public function validate_subject_tag($tag)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (!(preg_match("/^[ \w-\.\[\]]+$/", $tag)))
            return lang('mail_filter_subject_tag_invalid');
    }

    /**
     * Validation routine for subject tag state.
     *
     * @param string $state subject tag state
     *
     * @return string error message if subject tag state is invalid
     */
    
    public function validate_subject_tag_state($state)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (!clearos_is_valid_boolean($state))
            return lang('mail_filter_subject_tag_state_invalid');
    }

    /**
     * Validation routine for subject tag level.
     *
     * @param string $level subject tag level
     *
     * @return string error message if subject tag level is invalid
     */
    
    public function validate_subject_tag_level($level)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (preg_match("/^[0-9]+$/", $level))
            return;

        if (preg_match("/^[0-9]+\.[0-9]{1,2}$/", $level))
            return;

        return lang('mail_filter_subject_tag_level_invalid');
    }

    ///////////////////////////////////////////////////////////////////////////////
    // P R I V A T E  M E T H O D S
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * Loads configuration values.
     *
     * @access private
     * @return void
     * @throws Engine_Exception
     */

    protected function _load_config()
    {
        clearos_profile(__METHOD__, __LINE__);

        $file = new File(self::FILE_CONFIG);
        $lines = $file->get_contents_as_array();
        $is_banned_filename = FALSE;
        $current = "";

        foreach ($lines as $line) {
            $matches = array();

            if (preg_match('/^\s*\$(.*)\s*=\s*(.*);/', $line, $matches)) {
                $value = preg_replace("/['\"]/", "", $matches[2]);
                $this->params[trim($matches[1])] = $value;
            } else if (preg_match('/^\s*@(.*)\s*=\s*(.*);/', $line, $matches)) {
                $value = preg_replace("/['\"]/", "", $matches[2]);
                $this->params[trim($matches[1])] = $value;
            } else if (preg_match("/banned_filename_re\s*=/", $line)) {
                // The rest of the logic is for parsing banned_filename_re
                $is_banned_filename = TRUE;
            } else if (preg_match("/;\s*$/", $line)) {
                $is_banned_filename = FALSE;
            } else if ($is_banned_filename && preg_match("/#\s*(.*)/", $line, $matches)) {
                $current = $matches[1];
            } else if (($current == self::CONSTANT_BANNED_EXTENSIONS) && (preg_match('/^\s*qr\'\\\\.\((.*)\)/', $line, $matches))) {
                $this->banned_extensions = explode("|", $matches[1]);
                $current = "";
            } else if (($current == self::CONSTANT_DOUBLE_EXTENSIONS) && (preg_match('/^\s*qr([^\(]*)*\((.*)\)/', $line, $matches))) {
                $this->double_extensions = explode("|", $matches[1]);
                $current = "";
            } else if (($current == self::CONSTANT_MIME_TYPES) && (preg_match('/^\s*qr\'\^(.*)\$/', $line, $matches))) {
                $this->mime_types[] = $matches[1];
            }
        }

        $this->is_loaded = TRUE;
    }

    /**
     * Sets the subject tag.
     *
     * @param string $parameter key in configuration file
     * @param string $value     value for given parameter
     *
     * @access private
     * @return void
     * @throws Engine_Exception
     */

    protected function _set_parameter($parameter, $value)
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->is_loaded = FALSE;

        $file = new File(self::FILE_CONFIG);

        $parameter_preg = preg_quote($parameter);

        if ($value === self::CONSTANT_REMOVE_PARAMETER) {
            $file->replace_lines("/^\s*$parameter_preg\s*=/i", "");
        } else {
            if (empty($value))
                $value = "''";

            $match = $file->replace_lines("/^\s*$parameter_preg\s*=/i", "$parameter = $value;\n");

            if (!$match)
                $file->add_lines_before("$parameter = $value;\n", "/^1;$/");
        }
    }
}
