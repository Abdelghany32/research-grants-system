<?php
declare(strict_types=1);
// Creates the demo calls and proposals by calling the same workflow operations
// the screens use, as the fictional users. Every seeded row therefore passed
// the real permission checks and has a matching audit event.
require __DIR__ . '/../src/bootstrap.php';

use App\App;
use App\Auth\User;

$app = new App(require __DIR__ . '/../config/config.php');
$wf = $app->workflow();

$user = static function (string $email) use ($app): User {
    $stmt = $app->db()->pdo()->prepare('SELECT id, email, full_name, department, role FROM users WHERE email = ?');
    $stmt->execute([$email]);
    return User::fromRow($stmt->fetch());
};
$amina = $user('amina.elidrissi@uni.example');
$youssef = $user('youssef.benali@uni.example');
$salma = $user('salma.tazi@uni.example');
$karim = $user('karim.ouazzani@uni.example');
$nadia = $user('nadia.berrada@uni.example');
$in = static fn (int $days): string => gmdate('Y-m-d', time() + $days * 86400);

$ai = $wf->createCall($nadia, [
    'title' => 'Applied AI and Data Science Seed Fund 2027',
    'description' => 'Seed funding for early-stage projects that apply machine learning to education, health or public services.',
    'currency' => 'MAD', 'total_budget' => '600000.00', 'closes_on' => $in(45),
]);
$infra = $wf->createCall($nadia, [
    'title' => 'Sustainable Infrastructure Research Call',
    'description' => 'Pilot studies on water, energy and resilient construction for the region.',
    'currency' => 'MAD', 'total_budget' => '250000.00', 'closes_on' => $in(20),
]);

$abstract = static fn (string $topic): string =>
    "This fictional proposal studies $topic. The project runs for twelve months, " .
    'involves two doctoral students, and will publish its data and methods openly. ' .
    'The requested budget covers equipment, field work and dissemination.';

// 1. Under review with a completed review: ready for the officer's decision.
$p1 = $wf->createDraft($amina, $ai, ['title' => 'Federated Learning for Privacy-Preserving Student Analytics',
    'abstract' => $abstract('how universities can learn from student data without centralising it'), 'requested_amount' => '180000']);
$wf->submitProposal($amina, $p1);
$r1 = $wf->assignReviewer($nadia, $p1, $salma->id, $in(14));
$wf->saveReview($salma, $r1, ['score' => '8', 'comments' =>
    'Strong method and a realistic plan. The privacy evaluation needs a clearer threat model. Recommend funding.'], true);

// 2. A draft that only its author can see.
$wf->createDraft($amina, $ai, ['title' => 'Low-Resource Darija Speech Recognition',
    'abstract' => '', 'requested_amount' => '95000']);

// 3. Under review, review still pending (assigned to the other reviewer).
$p3 = $wf->createDraft($youssef, $infra, ['title' => 'Seismic Retrofitting of Rammed-Earth Heritage Structures',
    'abstract' => $abstract('low-cost reinforcement techniques for historic earthen buildings'), 'requested_amount' => '140000']);
$wf->submitProposal($youssef, $p3);
$wf->assignReviewer($nadia, $p3, $karim->id, $in(10));

// 4. Submitted, waiting for a reviewer.
$p4 = $wf->createDraft($youssef, $infra, ['title' => 'Solar-Powered Desalination Membranes: A Pilot Study',
    'abstract' => $abstract('membrane fouling in small solar desalination units'), 'requested_amount' => '120000']);
$wf->submitProposal($youssef, $p4);

// 5. Approved for less than requested: the call balance drops by the award.
$p5 = $wf->createDraft($youssef, $infra, ['title' => 'Greywater Reuse Monitoring for Campus Buildings',
    'abstract' => $abstract('sensor-based monitoring of greywater reuse in student residences'), 'requested_amount' => '60000']);
$wf->submitProposal($youssef, $p5);
$r5 = $wf->assignReviewer($nadia, $p5, $salma->id, null);
$wf->saveReview($salma, $r5, ['score' => '7', 'comments' =>
    'Useful and feasible. The sensor budget looks slightly high; a reduced award is reasonable.'], true);
$wf->recordDecision($nadia, $p5, 'approved', '55000.00', 'Approved with a reduced equipment budget.');

// 6. Declined. The title contains an apostrophe on purpose (search regression case).
$p6 = $wf->createDraft($amina, $ai, ['title' => "Children's Digital Literacy in Rural Schools",
    'abstract' => $abstract('digital literacy programmes for primary schools outside large cities'), 'requested_amount' => '210000']);
$wf->submitProposal($amina, $p6);
$r6 = $wf->assignReviewer($nadia, $p6, $karim->id, null);
$wf->saveReview($karim, $r6, ['score' => '4', 'comments' =>
    'Important topic but the evaluation design is not yet convincing. Encourage resubmission.'], true);
$wf->recordDecision($nadia, $p6, 'declined', '', 'Not funded in this round. Please strengthen the evaluation design and reapply.');

echo "seeded 2 calls and 6 proposals in database {$app->config['db']['name']}\n";
