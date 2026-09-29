describe('/#/privacy-security/data-export', () => {
  describe('order data isolation', () => {
    beforeEach(() => {
      cy.visit('/#/register')

      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#emailControl').type(`admun@${appDomain}`)
        }
      )
      cy.get('#passwordControl').focus().type('admun123')
      cy.get('#repeatPasswordControl').focus().type('admun123')

      cy.get('mat-select[name="securityQuestion"]').focus().click({ force: true })
      cy.get('.mat-mdc-option')
        .contains('Your eldest siblings middle name?')
        .click()

      cy.get('#securityAnswerControl').focus().type('admun')
      cy.get('#registerButton').click()
    })

    it('should not expose orders of a user whose email only differs in its vowels', () => {
      // 'admun@...' used to collide with 'admin@...' because orders were
      // resolved by a vowel-masked email instead of the UserId.
      cy.login({ email: 'admun', password: 'admun123' })

      cy.window().then((window) => {
        cy.request({
          method: 'GET',
          url: '/rest/order-history',
          headers: {
            Authorization: `Bearer ${window.localStorage.getItem('token')}`
          }
        }).then((response) => {
          expect(response.status).to.equal(200)
          expect(response.body.data).to.deep.equal([])
        })
      })
    })
  })
})
