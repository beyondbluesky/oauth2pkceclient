<?php

/* 
 *  The Creative Commons BY-NC-SA 4.0 License
 *  Attribution-NonCommercial-ShareAlike 4.0 International
 * 
 *  Josep Llauradó Selvas
 *  pep@beyondbluesky.com
 * 
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */


namespace BeyondBlueSky\OAuth2PKCEClient\Repository;

use BeyondBlueSky\OAuth2PKCEClient\Entity\OAuth2Session;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;

use Symfony\Component\DependencyInjection\ContainerInterface;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Common\Persistence\ManagerRegistry;

/**
 * @method OAuth2Session|null find($id, $lockMode = null, $lockVersion = null)
 * @method OAuth2Session|null findOneBy(array $criteria, array $orderBy = null)
 * @method OAuth2Session[]    findAll()
 * @method OAuth2Session[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class OAuth2SessionRepository extends ServiceEntityRepository
{
    protected $_em;
    protected $_container;
    
    public function __construct(EntityManagerInterface $manager, ContainerInterface $container, ManagerRegistry $registry) {
        $this->_em = $manager;
        $this->_container = $container;
        
        parent::__construct($registry, OAuth2Session::class);
    }
    
    public function findByAudience(string $userId, string $audience): ?OAuth2Session {
        
        return $this->findOneBy(['userId'=> $userId,'audience'=>$audience],['id'=>'DESC']);
    }
    
    public function persist(OAuth2Session $session){
        $this->_em->persist($session);
        $this->_em->flush();
    }
    
    // /**
    //  * @return OAuth2Session[] Returns an array of OAuth2Session objects
    //  */
    /*
    public function findByExampleField($value)
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.exampleField = :val')
            ->setParameter('val', $value)
            ->orderBy('u.id', 'ASC')
            ->setMaxResults(10)
            ->getQuery()
            ->getResult()
        ;
    }
    */

    /*
    public function findOneBySomeField($value): ?OAuth2Session
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.exampleField = :val')
            ->setParameter('val', $value)
            ->getQuery()
            ->getOneOrNullResult()
        ;
    }
    */
}
